//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package oauthserver

import (
	"os"
	"syscall"

	"github.com/ifloppy/chat-with-cli/internal/securefile"
)

func withStateFileLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return os.ErrPermission
		}
		if err := securefile.CheckSingleLink(info, "OAuth state lock"); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	lock, err := securefile.Open(lockPath, os.O_CREATE|os.O_RDWR, 0o600, "OAuth state lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lock.Chmod(0o600); err != nil {
		return err
	}
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return os.ErrPermission
	}
	if err := securefile.CheckSingleLink(info, "OAuth state lock"); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}
