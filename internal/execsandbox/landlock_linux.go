//go:build linux

package execsandbox

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"unsafe"
)

const (
	landlockCreateRulesetVersion = 1
	landlockRulePathBeneath      = 1
)

func landlockAccessRights() (readAccess, writeAccess, denyOnlyAccess uint64, err error) {
	abi, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION), 0, 0, 0)
	if errno != 0 {
		return 0, 0, 0, fmt.Errorf("query Landlock ABI: %w", errno)
	}
	// ABI 3 is the first version that can deny truncate(2), but ABI 5 also
	// lets us deny device ioctl(2). The Developer profile treats Landlock as
	// a real security boundary, so fail closed instead of silently degrading.
	if abi < 5 {
		return 0, 0, 0, fmt.Errorf("Landlock ABI %d is too old for the secure exec profile; ABI 5 or newer is required (use --exec-sandbox=none only if you explicitly accept the weaker boundary)", abi)
	}

	readAccess = uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	writeAccess = uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	// Newly opened character/block devices should not gain arbitrary ioctl
	// authority merely because runtime paths such as /dev are readable.
	denyOnlyAccess = uint64(unix.LANDLOCK_ACCESS_FS_IOCTL_DEV)
	return readAccess, writeAccess, denyOnlyAccess, nil
}

func Apply(roots []string, allowWrite bool, tempDir string) error {
	readAccess, writeAccess, denyOnlyAccess, err := landlockAccessRights()
	if err != nil {
		return err
	}
	// Landlock only denies access rights named in handled_access_fs. Always
	// handle mutating rights even for a read-only sandbox; omitting them would
	// make writes unrestricted rather than denied. Rules below decide where
	// those handled rights are actually granted.
	handled := readAccess | writeAccess | denyOnlyAccess
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	ruleset, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("Landlock is unavailable (kernel returned %v)", errno)
	}
	defer unix.Close(int(ruleset))

	grant := func(path string, access uint64) error {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil
			}
			return err
		}
		defer unix.Close(fd)
		rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, ruleset, landlockRulePathBeneath, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		if errno != 0 {
			return errno
		}
		return nil
	}

	// A command still needs to load its interpreter, shared libraries, device
	// nodes, and common runtime metadata. These paths are read/execute only;
	// workspace roots receive write access only when explicitly requested.
	for _, path := range []string{"/bin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/run"} {
		if err := grant(path, readAccess); err != nil {
			return fmt.Errorf("allow runtime path %s: %w", path, err)
		}
	}
	// Common shell/runtime code opens these device nodes for output. Grant only
	// WRITE_FILE on the nodes themselves; never grant directory mutation rights
	// to /dev as a whole.
	for _, path := range []string{"/dev/null", "/dev/tty", "/dev/ptmx"} {
		if err := grant(path, uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE)); err != nil {
			return fmt.Errorf("allow runtime device %s: %w", path, err)
		}
	}
	if allowWrite {
		tempDir = filepath.Clean(strings.TrimSpace(tempDir))
		if tempDir == "." || tempDir == "" {
			return errors.New("write-enabled Landlock sandbox requires a private temporary directory")
		}
		if err := grant(tempDir, readAccess|writeAccess); err != nil {
			return fmt.Errorf("allow private temporary path %s: %w", tempDir, err)
		}
	}
	for _, root := range roots {
		root = filepath.Clean(root)
		access := readAccess
		if allowWrite {
			access |= writeAccess
		}
		if err := grant(root, access); err != nil {
			return fmt.Errorf("allow workspace root %s: %w", root, err)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no-new-privileges: %w", err)
	}
	_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("restrict process with Landlock: %w", errno)
	}
	return nil
}
