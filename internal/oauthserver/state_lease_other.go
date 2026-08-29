//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package oauthserver

import "errors"

type stateLease struct{}

func acquireStateLease(string) (*stateLease, error) {
	return nil, errors.New("OAuth Relay single-writer state lease is unsupported on this platform")
}

func (*stateLease) Close() error { return nil }
