//go:build linux

package securefile

import (
	"os"

	"golang.org/x/sys/unix"
)

func openPrivate(path string, flags int, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(perm.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
