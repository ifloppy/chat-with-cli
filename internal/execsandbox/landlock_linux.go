//go:build linux

package execsandbox

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
	"unsafe"
)

const (
	landlockCreateRulesetVersion = 1
	landlockRulePathBeneath      = 1
)

func Apply(roots []string, allowWrite bool) error {
	readAccess := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	writeAccess := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	handled := readAccess | writeAccess
	if !allowWrite {
		handled = readAccess
	}
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
	if allowWrite {
		if err := grant("/tmp", readAccess|writeAccess); err != nil {
			return fmt.Errorf("allow temporary path: %w", err)
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
