package oauthserver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const systemStateRoot = "/var/lib"

func secureOAuthStateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create OAuth state directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect OAuth state directory: %w", err)
	}
	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("secure OAuth state directory: %w", err)
		}
		return nil
	}
	if info.Mode()&os.ModeSymlink == 0 || !isSystemdPrivateStateLink(path, systemStateRoot) {
		return errors.New("OAuth state directory must be a real directory or a verified systemd StateDirectory link")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("secure OAuth state directory: %w", err)
	}
	return nil
}

func isSystemdPrivateStateLink(path, root string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	abs, root = filepath.Clean(abs), filepath.Clean(root)
	if filepath.Dir(abs) != root || filepath.Base(abs) == "." {
		return false
	}
	rootInfo, err := os.Stat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o022 != 0 {
		return false
	}
	privateRoot := filepath.Join(root, "private")
	privateInfo, err := os.Stat(privateRoot)
	if err != nil || !privateInfo.IsDir() || privateInfo.Mode().Perm()&0o022 != 0 {
		return false
	}
	wantRelative := filepath.Join("private", filepath.Base(abs))
	target, err := os.Readlink(abs)
	if err != nil || filepath.Clean(target) != wantRelative {
		return false
	}
	resolved := filepath.Join(privateRoot, filepath.Base(abs))
	resolvedInfo, err := os.Lstat(resolved)
	if err != nil || !resolvedInfo.IsDir() || resolvedInfo.Mode()&os.ModeSymlink != 0 {
		return false
	}
	followedInfo, err := os.Stat(abs)
	return err == nil && os.SameFile(followedInfo, resolvedInfo)
}
