//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package oauthclient

// Platforms without a portable advisory file-lock primitive still retain the
// Manager's in-process mutex. The credential file remains atomic and
// permissioned; native per-platform locking can be added without changing the
// store format.
func withCredentialStoreLock(_ string, fn func() error) error { return fn() }
