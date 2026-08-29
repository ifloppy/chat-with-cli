//go:build !linux

package engine

import (
	"errors"
	"os"
	"path/filepath"
)

func (e *Engine) secureOpenRead(path string) (*os.File, string, error) {
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return nil, "", err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, "", err
	}
	return file, resolved, nil
}

func (e *Engine) secureOpenAppend(path string) (*os.File, string, error) {
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return nil, "", err
	}

	if info, err := os.Lstat(resolved); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, "", errors.New("refusing to append to a non-regular file or symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	file, err := os.OpenFile(resolved, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, "", err
	}
	return file, resolved, nil
}

func (e *Engine) secureAtomicWrite(path string, data []byte, fallbackMode os.FileMode) (string, error) {
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return "", err
	}
	mode := fallbackMode
	if info, err := os.Lstat(resolved); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("refusing to replace a non-regular file or symlink")
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := atomicWriteFileMode(resolved, data, mode); err != nil {
		return "", err
	}
	return resolved, nil
}
