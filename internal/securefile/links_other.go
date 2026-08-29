//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package securefile

import "os"

// Platforms without a portable link-count field still retain the symlink,
// regular-file, mode, and atomic-write checks performed by each caller.
func checkSingleLink(os.FileInfo, string) error { return nil }
