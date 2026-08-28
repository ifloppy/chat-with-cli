//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package oauthclient

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// withCredentialStoreLock serializes credential reads, refresh-token rotation,
// and atomic replacement across multiple Agent processes. Without the
// cross-process lock, two reconnecting Agents could refresh the same token at
// once; one replacement would then look like a replay and revoke the family.
func withCredentialStoreLock(path string, fn func() error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err != nil {
		return err
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("credential store directory must be a real directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	lockPath := path + ".lock"
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("credential store lock must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lock.Chmod(0o600); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}
