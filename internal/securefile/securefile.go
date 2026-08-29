// Package securefile contains small checks shared by files that hold
// credentials, authorization state, or security metadata.
package securefile

import (
	"errors"
	"io"
	"os"
)

// CheckSingleLink rejects a regular file with more than one directory entry.
// A private state directory should never contain such a file: an unexpected
// hardlink can make append-style writes affect an unrelated path and is a
// useful signal that the state boundary has been tampered with.
func CheckSingleLink(info os.FileInfo, label string) error {
	if info == nil {
		return errors.New("cannot inspect private file")
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	return checkSingleLink(info, label)
}

// Open opens a private regular file without following a final symlink. The
// path is checked before and after opening; if an existing pathname was
// replaced while opening, the descriptor is rejected unless it is still the
// same inode.
func Open(path string, flags int, perm os.FileMode, label string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New(label + " must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New(label + " must be a regular file")
		}
		if err := CheckSingleLink(info, label); err != nil {
			return nil, err
		}
	}
	file, err := openPrivate(path, flags, perm)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New(label + " must be a regular file")
	}
	if info != nil && !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New(label + " changed while opening")
	}
	if err := CheckSingleLink(opened, label); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// Read opens and reads a private regular file without following a final
// symlink. The file is checked again after opening so a replacement race or a
// hardlink cannot turn a private read into an arbitrary-file read.
func Read(path, label string) ([]byte, error) {
	file, err := Open(path, os.O_RDONLY, 0, label)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}
