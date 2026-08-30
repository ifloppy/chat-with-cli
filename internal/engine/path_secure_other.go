//go:build !linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ifloppy/chat-with-cli/internal/securefile"
)

func (e *Engine) secureOpenRead(path string) (*os.File, string, error) {
	if err := e.rejectSymlinkComponents(path); err != nil {
		return nil, "", err
	}
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return nil, "", err
	}
	before, err := os.Lstat(resolved)
	if err != nil {
		return nil, "", err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("refusing to follow a symlink")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, "", err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("path is not a regular file")
	}
	if !os.SameFile(before, info) {
		_ = file.Close()
		return nil, "", errors.New("file changed while opening")
	}
	if err := securefile.CheckSingleLink(info, "file"); err != nil {
		_ = file.Close()
		return nil, "", err
	}
	return file, resolved, nil
}

func (e *Engine) secureOpenAppend(path string) (*os.File, string, error) {
	if err := e.rejectSymlinkComponents(path); err != nil {
		return nil, "", err
	}
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return nil, "", err
	}

	var before os.FileInfo
	if info, err := os.Lstat(resolved); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, "", errors.New("refusing to append to a non-regular file or symlink")
		}
		before = info
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	file, err := os.OpenFile(resolved, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, "", err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("append target is not a regular file")
	}
	if before != nil && !os.SameFile(before, info) {
		_ = file.Close()
		return nil, "", errors.New("append target changed while opening")
	}
	if err := securefile.CheckSingleLink(info, "file"); err != nil {
		_ = file.Close()
		return nil, "", err
	}
	return file, resolved, nil
}

func (e *Engine) secureAtomicWrite(path string, data []byte, fallbackMode os.FileMode) (string, error) {
	if err := e.rejectSymlinkComponents(path); err != nil {
		return "", err
	}
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return "", err
	}
	mode := fallbackMode
	if info, err := os.Lstat(resolved); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("refusing to replace a non-regular file or symlink")
		}
		if err := securefile.CheckSingleLink(info, "file"); err != nil {
			return "", err
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := atomicWriteFileMode(resolved, data, mode); err != nil {
		return "", err
	}
	return resolved, nil
}

func (e *Engine) rejectSymlinkComponents(path string) error {
	candidate := strings.TrimSpace(path)
	if candidate == "" {
		return errors.New("path must not be empty")
	}
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(e.roots[0], candidate)
	}
	candidate = filepath.Clean(candidate)
	for _, root := range e.roots {
		if !pathWithin(root, candidate) {
			continue
		}
		rel, err := filepath.Rel(root, candidate)
		if err != nil {
			return err
		}
		current := root
		if rel == "." {
			return nil
		}
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			if part == "" || part == "." {
				continue
			}
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("refusing to operate through a symlink")
			}
		}
		return nil
	}
	return fmt.Errorf("path %q is outside allowed roots", path)
}

func (e *Engine) verifyRegularPath(ctx context.Context, path, expected, label string) error {
	if err := e.rejectSymlinkComponents(path); err != nil {
		return err
	}
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to operate on a symlink %s", label)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", label)
	}
	if err := securefile.CheckSingleLink(info, label); err != nil {
		return err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		if err != nil {
			return err
		}
		return errors.New("file changed while opening")
	}
	if err := securefile.CheckSingleLink(opened, label); err != nil {
		return err
	}
	actual, err := e.hashFileSHA256(file)
	if err != nil {
		return err
	}
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	return verifySHA256(expected, actual)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	err = dir.Sync()
	_ = dir.Close()
	return err
}

func (e *Engine) secureDelete(ctx context.Context, path, expected string, allowEmptyDir bool) error {
	if err := e.rejectSymlinkComponents(path); err != nil {
		return err
	}
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return err
	}
	for _, root := range e.roots {
		if filepath.Clean(root) == filepath.Clean(resolved) {
			return errors.New("refusing to delete an allowed root")
		}
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to delete a symlink")
	}
	if info.IsDir() {
		if expected != "" {
			return errors.New("expected_sha256 applies only to regular files")
		}
		if !allowEmptyDir {
			return errors.New("refusing to delete a directory unless allow_empty_dir is true")
		}
		if err := e.checkContext(ctx); err != nil {
			return err
		}
		if err := os.Remove(resolved); err != nil {
			return fmt.Errorf("delete empty directory: %w", err)
		}
		return syncDirectory(filepath.Dir(resolved))
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to delete a non-regular file")
	}
	if strings.TrimSpace(expected) == "" {
		return errors.New("expected_sha256 is required when deleting an existing file; call fs_read first")
	}
	if _, err := normalizedExpectedSHA256(expected); err != nil {
		return err
	}
	if err := e.verifyRegularPath(ctx, resolved, expected, "delete target"); err != nil {
		return err
	}
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	if err := os.Remove(resolved); err != nil {
		return fmt.Errorf("delete file: %w", err)
	}
	return syncDirectory(filepath.Dir(resolved))
}

func (e *Engine) secureMkdir(ctx context.Context, path string) error {
	if err := e.rejectSymlinkComponents(path); err != nil {
		return err
	}
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(resolved); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to create a directory through a symlink")
		}
		if !info.IsDir() {
			return errors.New("mkdir target exists and is not a directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(resolved, 0o755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	return syncDirectory(filepath.Dir(resolved))
}

func (e *Engine) secureMove(ctx context.Context, in FileMoveInput) (FileMoveOutput, error) {
	expectedSource, err := normalizedExpectedSHA256(in.ExpectedSHA256)
	if err != nil {
		return FileMoveOutput{}, err
	}
	if expectedSource == "" {
		return FileMoveOutput{}, errors.New("expected_sha256 is required when moving an existing file; call fs_read first")
	}
	expectedDestination, err := normalizedExpectedSHA256(in.ExpectedDestinationSHA256)
	if err != nil {
		return FileMoveOutput{}, err
	}
	if err := e.rejectSymlinkComponents(in.Source); err != nil {
		return FileMoveOutput{}, err
	}
	if err := e.rejectSymlinkComponents(in.Destination); err != nil {
		return FileMoveOutput{}, err
	}
	source, err := e.ResolvePath(in.Source)
	if err != nil {
		return FileMoveOutput{}, err
	}
	destination, err := e.ResolvePath(in.Destination)
	if err != nil {
		return FileMoveOutput{}, err
	}
	if source == destination {
		return FileMoveOutput{}, errors.New("source and destination must be different")
	}
	if err := e.verifyRegularPath(ctx, source, expectedSource, "move source"); err != nil {
		return FileMoveOutput{}, err
	}
	if info, statErr := os.Lstat(destination); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return FileMoveOutput{}, errors.New("refusing to replace a symlink destination")
		}
		if !info.Mode().IsRegular() {
			return FileMoveOutput{}, errors.New("destination must be a regular file")
		}
		if !in.Overwrite {
			return FileMoveOutput{}, errors.New("destination already exists; set overwrite=true with expected_destination_sha256 to replace it")
		}
		if expectedDestination == "" {
			return FileMoveOutput{}, errors.New("expected_destination_sha256 is required when overwrite is true")
		}
		if err := e.verifyRegularPath(ctx, destination, expectedDestination, "move destination"); err != nil {
			return FileMoveOutput{}, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return FileMoveOutput{}, statErr
	} else if expectedDestination != "" {
		return FileMoveOutput{}, errors.New("expected_destination_sha256 was supplied but destination does not exist")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return FileMoveOutput{}, err
	}
	if err := e.checkContext(ctx); err != nil {
		return FileMoveOutput{}, err
	}
	if in.Overwrite {
		if err := os.Rename(source, destination); err != nil {
			return FileMoveOutput{}, fmt.Errorf("move file: %w", err)
		}
	} else {
		// Link-then-unlink gives non-Linux callers a no-replace destination
		// primitive: link(2) fails atomically when the target appears.
		if err := os.Link(source, destination); err != nil {
			return FileMoveOutput{}, fmt.Errorf("move file without replacing destination: %w", err)
		}
		if err := os.Remove(source); err != nil {
			_ = os.Remove(destination)
			return FileMoveOutput{}, fmt.Errorf("remove moved source: %w", err)
		}
	}
	if err := syncDirectory(filepath.Dir(source)); err != nil {
		return FileMoveOutput{}, err
	}
	if filepath.Dir(destination) != filepath.Dir(source) {
		if err := syncDirectory(filepath.Dir(destination)); err != nil {
			return FileMoveOutput{}, err
		}
	}
	return FileMoveOutput{Source: source, Destination: destination}, nil
}

func (e *Engine) secureAtomicWriteIfUnchanged(ctx context.Context, path string, data []byte, fallbackMode os.FileMode, expected string) (string, error) {
	expected, err := normalizedExpectedSHA256(expected)
	if err != nil || expected == "" {
		return "", err
	}
	if err := e.rejectSymlinkComponents(path); err != nil {
		return "", err
	}
	resolved, err := e.ResolvePath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("refusing to replace a non-regular file or symlink")
	}
	if err := securefile.CheckSingleLink(info, "file"); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(resolved), ".chat-with-cli-write-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	defer os.Remove(tmpName)
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		cleanup()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := e.verifyRegularPath(ctx, resolved, expected, "compare-and-replace target"); err != nil {
		return "", err
	}
	if hook := e.beforeFileCommit; hook != nil {
		e.beforeFileCommit = nil
		hook()
	}
	if err := e.verifyRegularPath(ctx, resolved, expected, "compare-and-replace target"); err != nil {
		return "", err
	}
	if err := e.checkContext(ctx); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, resolved); err != nil {
		return "", fmt.Errorf("compare-and-replace file: %w", err)
	}
	if err := syncDirectory(filepath.Dir(resolved)); err != nil {
		return "", err
	}
	_ = fallbackMode
	return resolved, nil
}
