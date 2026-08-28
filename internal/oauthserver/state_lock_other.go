//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package oauthserver

func withStateFileLock(_ string, fn func() error) error { return fn() }
