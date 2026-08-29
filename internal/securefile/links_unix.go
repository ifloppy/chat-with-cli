//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package securefile

import (
	"fmt"
	"os"
	"syscall"
)

func checkSingleLink(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || stat.Nlink <= 1 {
		return nil
	}
	if label == "" {
		label = "private file"
	}
	return fmt.Errorf("%s must not have multiple hard links", label)
}
