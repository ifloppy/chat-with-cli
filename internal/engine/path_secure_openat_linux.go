//go:build linux

package engine

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// secureOpenBeneath opens a path relative to a directory descriptor using
// only openat(2). Android may terminate an app with SIGSYS on openat2(2),
// rather than return ENOSYS, so probing openat2 is not safe.
//
// Every intermediate component is opened as a real directory with O_NOFOLLOW.
// Call sites retain canonical root/protected-state checks and regular-file
// and hard-link checks where applicable.
func secureOpenBeneath(dirFD int, rel string, flags int) (int, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return -1, errors.New("path must be relative to the allowed root")
	}
	parts := strings.Split(rel, string(filepath.Separator))
	current := dirFD
	for i, part := range parts {
		if part == "" || part == ".." || (part == "." && len(parts) != 1) {
			if current != dirFD {
				_ = unix.Close(current)
			}
			return -1, errors.New("refusing unsafe relative path component")
		}

		openFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i == len(parts)-1 {
			openFlags = flags | unix.O_CLOEXEC | unix.O_NOFOLLOW
		}
		next, err := unix.Openat(current, part, openFlags, 0)
		if current != dirFD {
			_ = unix.Close(current)
		}
		if err != nil {
			return -1, err
		}
		current = next
	}
	return current, nil
}
