package oauthserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ifloppy/chat-with-cli/internal/securefile"
)

const (
	stateGuardClean = "clean\n"
	stateGuardDirty = "dirty\n"
)

func openStateGuard(stateDir string) (*os.File, bool, error) {
	path := filepath.Join(stateDir, "oauth-state.guard")
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, false, errors.New("OAuth state guard must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	file, err := securefile.Open(path, os.O_CREATE|os.O_RDWR, 0o600, "OAuth state guard")
	if err != nil {
		return nil, false, err
	}
	fail := func(err error) (*os.File, bool, error) {
		_ = file.Close()
		return nil, false, err
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(err)
	}
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(errors.New("OAuth state guard must be a regular file"))
	}
	if err := securefile.CheckSingleLink(info, "OAuth state guard"); err != nil {
		return fail(err)
	}
	data := make([]byte, 16)
	n, err := file.ReadAt(data, 0)
	if err != nil && !errors.Is(err, os.ErrNotExist) && n == 0 && info.Size() != 0 {
		return fail(err)
	}
	state := string(data[:n])
	if info.Size() == 0 {
		if err := writeStateGuard(file, stateGuardClean); err != nil {
			return fail(err)
		}
		dir, err := os.Open(stateDir)
		if err != nil {
			return fail(err)
		}
		err = dir.Sync()
		_ = dir.Close()
		if err != nil {
			return fail(err)
		}
		return file, false, nil
	}
	switch state {
	case stateGuardClean:
		return file, false, nil
	case stateGuardDirty:
		return file, true, nil
	default:
		return fail(fmt.Errorf("OAuth state guard contains invalid state"))
	}
}

func writeStateGuard(file *os.File, state string) error {
	if file == nil || (state != stateGuardClean && state != stateGuardDirty) {
		return errors.New("invalid OAuth state guard write")
	}
	if _, err := file.WriteAt([]byte(state), 0); err != nil {
		return err
	}
	if err := file.Truncate(int64(len(state))); err != nil {
		return err
	}
	return file.Sync()
}
