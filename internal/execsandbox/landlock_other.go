//go:build !linux

package execsandbox

import "errors"

func Apply(_ []string, _ bool) error {
	return errors.New("Landlock exec sandbox is supported on Linux only")
}
