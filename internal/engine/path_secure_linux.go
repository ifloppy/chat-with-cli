//go:build linux

package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/ifloppy/chat-with-cli/internal/securefile"
	"golang.org/x/sys/unix"
)

const secureResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS

func (e *Engine) rootRelativePath(path string) (root, rel string, err error) {
	candidate := strings.TrimSpace(path)
	if candidate == "" {
		return e.roots[0], ".", nil
	}
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(e.roots[0], candidate)
	}
	candidate = filepath.Clean(candidate)
	for _, root := range e.roots {
		rel, err := filepath.Rel(root, candidate)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return root, rel, nil
		}
	}
	return "", "", fmt.Errorf("path %q is outside allowed roots", path)
}

func openRootFD(root string) (int, error) {
	return unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

func fdCanonicalPath(fd int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "", err
	}
	return filepath.Clean(strings.TrimSuffix(path, " (deleted)")), nil
}

func (e *Engine) secureOpenRead(path string) (*os.File, string, error) {
	root, rel, err := e.rootRelativePath(path)
	if err != nil {
		return nil, "", err
	}
	rootFD, err := openRootFD(root)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: secureResolveFlags,
	})
	if err != nil {
		return nil, "", err
	}
	canonical, err := fdCanonicalPath(fd)
	if err != nil || !pathWithin(root, canonical) || e.isProtectedPath(canonical) {
		unix.Close(fd)
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("resolved path is outside the allowed root or reserved for chat-with-cli private state")
	}
	file := os.NewFile(uintptr(fd), canonical)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("resolved path is not a regular file")
	}
	if err := securefile.CheckSingleLink(info, "file"); err != nil {
		_ = file.Close()
		return nil, "", err
	}
	return file, canonical, nil
}

func openChildDir(parentFD int, name string, create bool) (int, error) {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: secureResolveFlags,
	})
	if err == nil || !create || !errors.Is(err, unix.ENOENT) {
		return fd, err
	}
	if err := unix.Mkdirat(parentFD, name, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	return unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: secureResolveFlags,
	})
}

func (e *Engine) secureParent(path string, create bool) (fd int, base, canonical string, err error) {
	root, rel, err := e.rootRelativePath(path)
	if err != nil {
		return -1, "", "", err
	}
	base = filepath.Base(rel)
	if base == "." || base == string(filepath.Separator) || base == ".." {
		return -1, "", "", errors.New("file path must include a filename")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", "", err
	}
	current := rootFD
	parentRel := filepath.Dir(rel)
	if parentRel != "." {
		for _, part := range strings.Split(parentRel, string(filepath.Separator)) {
			if part == "" || part == "." {
				continue
			}
			if part == ".." {
				unix.Close(current)
				return -1, "", "", errors.New("parent path escapes allowed root")
			}
			next, openErr := openChildDir(current, part, create)
			if current != rootFD {
				unix.Close(current)
			}
			if openErr != nil {
				unix.Close(rootFD)
				return -1, "", "", openErr
			}
			current = next
		}
	}

	if current != rootFD {
		unix.Close(rootFD)
	}
	parentCanonical, err := fdCanonicalPath(current)
	if err != nil {
		unix.Close(current)
		return -1, "", "", err
	}
	canonical = filepath.Join(parentCanonical, base)
	if !pathWithin(root, parentCanonical) || e.isProtectedPath(canonical) {
		unix.Close(current)
		return -1, "", "", errors.New("target path is outside the allowed root or reserved for chat-with-cli private state")
	}
	return current, base, canonical, nil
}

func (e *Engine) secureOpenAppend(path string) (*os.File, string, error) {
	parentFD, base, canonical, err := e.secureParent(path, true)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, base, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, "", err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("append target is not a regular file")
	}
	file := os.NewFile(uintptr(fd), canonical)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("append target is not a regular file")
	}
	if err := securefile.CheckSingleLink(info, "file"); err != nil {
		_ = file.Close()
		return nil, "", err
	}
	return file, canonical, nil
}

func secureExistingMode(parentFD int, base string, fallback os.FileMode) (os.FileMode, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return fallback, nil
	}
	if err != nil {
		return 0, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, errors.New("refusing to replace a non-regular file or symlink")
	}
	return os.FileMode(stat.Mode & 0o777), nil
}

func (e *Engine) secureAtomicWrite(path string, data []byte, fallbackMode os.FileMode) (string, error) {
	parentFD, base, canonical, err := e.secureParent(path, true)
	if err != nil {
		return "", err
	}
	defer unix.Close(parentFD)
	mode, err := secureExistingMode(parentFD, base, fallbackMode)
	if err != nil {
		return "", err
	}
	tmpName := ".chat-with-cli-write-" + protocol.NewID()
	fd, err := unix.Openat(parentFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), tmpName)
	cleanup := func() {
		_ = file.Close()
		_ = unix.Unlinkat(parentFD, tmpName, 0)
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", err
	}
	if err := unix.Renameat(parentFD, tmpName, parentFD, base); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return "", err
	}
	return canonical, nil
}
