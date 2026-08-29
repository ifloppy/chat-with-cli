//go:build !linux

package securefile

import "os"

func openPrivate(path string, flags int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags, perm)
}
