//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package oauthserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type stateLease struct {
	file *os.File
}

func acquireStateLease(stateDir string) (*stateLease, error) {
	path := filepath.Join(stateDir, "oauth-state.lease")
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("OAuth state lease must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another Relay process already holds the OAuth state lease for %s", stateDir)
		}
		return nil, err
	}
	return &stateLease{file: file}, nil
}

func (l *stateLease) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}
