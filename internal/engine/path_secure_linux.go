//go:build linux

package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/ifloppy/chat-with-cli/internal/securefile"
	"golang.org/x/sys/unix"
)

const secureResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS

func (e *Engine) rootRelativePath(path string) (root, rel string, err error) {
	candidate := strings.TrimSpace(path)
	if candidate == "" {
		return e.roots[0], ".", nil
	}
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(e.roots[0], candidate)
	}
	candidate = filepath.Clean(candidate)
	for _, root := range e.roots {
		rel, err := filepath.Rel(root, candidate)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return root, rel, nil
		}
	}
	return "", "", fmt.Errorf("path %q is outside allowed roots", path)
}

func openRootFD(root string) (int, error) {
	return unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

func fdCanonicalPath(fd int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "", err
	}
	return filepath.Clean(strings.TrimSuffix(path, " (deleted)")), nil
}

func (e *Engine) secureOpenRead(path string) (*os.File, string, error) {
	root, rel, err := e.rootRelativePath(path)
	if err != nil {
		return nil, "", err
	}
	rootFD, err := openRootFD(root)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: secureResolveFlags,
	})
	if err != nil {
		return nil, "", err
	}
	canonical, err := fdCanonicalPath(fd)
	if err != nil || !pathWithin(root, canonical) || e.isProtectedPath(canonical) {
		unix.Close(fd)
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("resolved path is outside the allowed root or reserved for chat-with-cli private state")
	}
	file := os.NewFile(uintptr(fd), canonical)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("resolved path is not a regular file")
	}
	if err := securefile.CheckSingleLink(info, "file"); err != nil {
		_ = file.Close()
		return nil, "", err
	}
	return file, canonical, nil
}

func openChildDir(parentFD int, name string, create bool) (int, error) {
	var stat unix.Stat_t
	if statErr := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); statErr == nil {
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			return -1, errors.New("refusing to operate through a symlink")
		}
	} else if !errors.Is(statErr, unix.ENOENT) {
		return -1, statErr
	}
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: secureResolveFlags,
	})
	if err == nil || !create || !errors.Is(err, unix.ENOENT) {
		return fd, err
	}
	if err := unix.Mkdirat(parentFD, name, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	return unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: secureResolveFlags,
	})
}

func (e *Engine) secureParent(path string, create bool) (fd int, base, canonical string, err error) {
	root, rel, err := e.rootRelativePath(path)
	if err != nil {
		return -1, "", "", err
	}
	base = filepath.Base(rel)
	if base == "." || base == string(filepath.Separator) || base == ".." {
		return -1, "", "", errors.New("file path must include a filename")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", "", err
	}
	current := rootFD
	currentCanonical := root
	parentRel := filepath.Dir(rel)
	if parentRel != "." {
		for _, part := range strings.Split(parentRel, string(filepath.Separator)) {
			if part == "" || part == "." {
				continue
			}
			if part == ".." {
				unix.Close(current)
				return -1, "", "", errors.New("parent path escapes allowed root")
			}
			candidateCanonical := filepath.Join(currentCanonical, part)
			if e.isProtectedPath(candidateCanonical) {
				if current != rootFD {
					unix.Close(current)
				}
				unix.Close(rootFD)
				return -1, "", "", errors.New("target path is outside the allowed root or reserved for chat-with-cli private state")
			}
			next, openErr := openChildDir(current, part, create)
			if current != rootFD {
				unix.Close(current)
			}
			if openErr != nil {
				unix.Close(rootFD)
				return -1, "", "", openErr
			}
			actualCanonical, canonicalErr := fdCanonicalPath(next)
			if canonicalErr != nil || !pathWithin(root, actualCanonical) || e.isProtectedPath(actualCanonical) {
				unix.Close(next)
				unix.Close(rootFD)
				if canonicalErr != nil {
					return -1, "", "", canonicalErr
				}
				return -1, "", "", errors.New("target path is outside the allowed root or reserved for chat-with-cli private state")
			}
			current = next
			currentCanonical = actualCanonical
		}
	}

	if current != rootFD {
		unix.Close(rootFD)
	}
	parentCanonical, err := fdCanonicalPath(current)
	if err != nil {
		unix.Close(current)
		return -1, "", "", err
	}
	canonical = filepath.Join(parentCanonical, base)
	if !pathWithin(root, parentCanonical) || e.isProtectedPath(canonical) {
		unix.Close(current)
		return -1, "", "", errors.New("target path is outside the allowed root or reserved for chat-with-cli private state")
	}
	return current, base, canonical, nil
}

func (e *Engine) secureOpenAppend(path string) (*os.File, string, error) {
	parentFD, base, canonical, err := e.secureParent(path, true)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, base, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, "", err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("append target is not a regular file")
	}
	file := os.NewFile(uintptr(fd), canonical)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, "", err
		}
		return nil, "", errors.New("append target is not a regular file")
	}
	if err := securefile.CheckSingleLink(info, "file"); err != nil {
		_ = file.Close()
		return nil, "", err
	}
	return file, canonical, nil
}

func secureExistingMode(parentFD int, base string, fallback os.FileMode) (os.FileMode, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return fallback, nil
	}
	if err != nil {
		return 0, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, errors.New("refusing to replace a non-regular file or symlink")
	}
	if stat.Nlink > 1 {
		return 0, errors.New("file must not have multiple hard links")
	}
	return os.FileMode(stat.Mode & 0o777), nil
}

func (e *Engine) openRegularAt(parentFD int, base, label string) (*os.File, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return nil, fmt.Errorf("refusing to operate on a symlink %s", label)
	case unix.S_IFREG:
	default:
		return nil, fmt.Errorf("%s must be a regular file", label)
	}
	if stat.Nlink > 1 {
		return nil, fmt.Errorf("%s must not have multiple hard links", label)
	}
	fd, err := unix.Openat2(parentFD, base, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: secureResolveFlags,
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), base)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s must be a regular file", label)
	}
	if err := securefile.CheckSingleLink(info, label); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (e *Engine) verifyRegularAt(ctx context.Context, parentFD int, base, expected, label string) error {
	file, err := e.openRegularAt(parentFD, base, label)
	if err != nil {
		return err
	}
	defer file.Close()
	actual, err := e.hashFileSHA256(file)
	if err != nil {
		return err
	}
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	return verifySHA256(expected, actual)
}

func (e *Engine) secureDelete(ctx context.Context, path, expected string, allowEmptyDir bool) error {
	expected, err := normalizedExpectedSHA256(expected)
	if err != nil {
		return err
	}
	parentFD, base, _, err := e.secureParent(path, false)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return errors.New("refusing to delete a symlink")
	case unix.S_IFDIR:
		if expected != "" {
			return errors.New("expected_sha256 applies only to regular files")
		}
		if !allowEmptyDir {
			return errors.New("refusing to delete a directory unless allow_empty_dir is true")
		}
		if err := e.checkContext(ctx); err != nil {
			return err
		}
		return e.deleteAtWithSnapshot(ctx, parentFD, base, true, "empty directory", "")
	case unix.S_IFREG:
		if expected == "" {
			return errors.New("expected_sha256 is required when deleting an existing file; call fs_read first")
		}
		if err := e.verifyRegularAt(ctx, parentFD, base, expected, "delete target"); err != nil {
			return err
		}
		if err := e.checkContext(ctx); err != nil {
			return err
		}
		return e.deleteAtWithSnapshot(ctx, parentFD, base, false, "file", expected)
	default:
		return errors.New("refusing to delete a non-regular file")
	}
}

// deleteAtWithSnapshot first moves the exact directory entry to a private
// tombstone with RENAME_NOREPLACE, then validates/deletes that detached entry.
// This closes the verify-then-unlink race: a replacement that appears at the
// original path is never unlinked as a consequence of an older snapshot.
func (e *Engine) deleteAtWithSnapshot(ctx context.Context, parentFD int, base string, directory bool, label, expected string) error {
	tombstone := ".chat-with-cli-delete-" + protocol.NewID()
	if hook := e.beforeFileCommit; hook != nil {
		e.beforeFileCommit = nil
		hook()
	}
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	if err := unix.Renameat2(parentFD, base, parentFD, tombstone, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("stage %s for deletion: %w", label, err)
	}
	restore := func(cause error) error {
		if restoreErr := unix.Renameat2(parentFD, tombstone, parentFD, base, unix.RENAME_NOREPLACE); restoreErr != nil {
			return fmt.Errorf("%w; restore %s after failed delete: %v", cause, label, restoreErr)
		}
		return cause
	}
	if !directory {
		if err := e.verifyRegularAt(ctx, parentFD, tombstone, expected, "staged delete target"); err != nil {
			return restore(err)
		}
	} else {
		var stat unix.Stat_t
		if err := unix.Fstatat(parentFD, tombstone, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			if err != nil {
				return restore(err)
			}
			return restore(errors.New("staged empty directory changed before deletion"))
		}
	}
	if err := e.checkContext(ctx); err != nil {
		return restore(err)
	}
	if directory {
		if err := unix.Unlinkat(parentFD, tombstone, unix.AT_REMOVEDIR); err != nil {
			return restore(fmt.Errorf("delete empty directory: %w", err))
		}
	} else if err := unix.Unlinkat(parentFD, tombstone, 0); err != nil {
		return restore(fmt.Errorf("delete file: %w", err))
	}
	return unix.Fsync(parentFD)
}

func (e *Engine) secureMkdir(ctx context.Context, path string) error {
	root, rel, err := e.rootRelativePath(path)
	if err != nil {
		return err
	}
	if rel == "." {
		if e.isProtectedPath(root) {
			return errors.New("target path is reserved for chat-with-cli private state")
		}
		return nil
	}
	parentFD, base, _, err := e.secureParent(path, true)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			return errors.New("refusing to create a directory through a symlink")
		case unix.S_IFDIR:
			return nil
		default:
			return errors.New("mkdir target exists and is not a directory")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	if err := unix.Mkdirat(parentFD, base, 0o755); err != nil {
		if errors.Is(err, unix.EEXIST) {
			if statErr := unix.Fstatat(parentFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW); statErr == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR {
				return nil
			}
		}
		return fmt.Errorf("create directory: %w", err)
	}
	return unix.Fsync(parentFD)
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
	sourceParent, sourceBase, sourceCanonical, err := e.secureParent(in.Source, false)
	if err != nil {
		return FileMoveOutput{}, err
	}
	defer unix.Close(sourceParent)
	destinationParent, destinationBase, destinationCanonical, err := e.secureParent(in.Destination, true)
	if err != nil {
		return FileMoveOutput{}, err
	}
	defer unix.Close(destinationParent)
	if sourceCanonical == destinationCanonical {
		return FileMoveOutput{}, errors.New("source and destination must be different")
	}
	if err := e.verifyRegularAt(ctx, sourceParent, sourceBase, expectedSource, "move source"); err != nil {
		return FileMoveOutput{}, err
	}

	var destinationStat unix.Stat_t
	destinationExists := true
	if err := unix.Fstatat(destinationParent, destinationBase, &destinationStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return FileMoveOutput{}, err
		}
		destinationExists = false
	}
	if !destinationExists {
		if expectedDestination != "" {
			return FileMoveOutput{}, errors.New("expected_destination_sha256 was supplied but destination does not exist")
		}
	} else {
		switch destinationStat.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			return FileMoveOutput{}, errors.New("refusing to replace a symlink destination")
		case unix.S_IFREG:
		default:
			return FileMoveOutput{}, errors.New("destination must be a regular file")
		}
		if !in.Overwrite {
			return FileMoveOutput{}, errors.New("destination already exists; set overwrite=true with expected_destination_sha256 to replace it")
		}
		if expectedDestination == "" {
			return FileMoveOutput{}, errors.New("expected_destination_sha256 is required when overwrite is true")
		}
		if err := e.verifyRegularAt(ctx, destinationParent, destinationBase, expectedDestination, "move destination"); err != nil {
			return FileMoveOutput{}, err
		}
	}
	if hook := e.beforeFileCommit; hook != nil {
		e.beforeFileCommit = nil
		hook()
	}
	if err := e.checkContext(ctx); err != nil {
		return FileMoveOutput{}, err
	}

	if !destinationExists || !in.Overwrite {
		if err := unix.Renameat2(sourceParent, sourceBase, destinationParent, destinationBase, unix.RENAME_NOREPLACE); err != nil {
			return FileMoveOutput{}, fmt.Errorf("move file without replacing destination: %w", err)
		}
		if err := e.verifyRegularAt(ctx, destinationParent, destinationBase, expectedSource, "moved source"); err != nil {
			restoreErr := unix.Renameat2(destinationParent, destinationBase, sourceParent, sourceBase, unix.RENAME_NOREPLACE)
			if restoreErr != nil {
				return FileMoveOutput{}, fmt.Errorf("%w; move rollback failed: %v", err, restoreErr)
			}
			_ = unix.Fsync(sourceParent)
			_ = unix.Fsync(destinationParent)
			return FileMoveOutput{}, err
		}
	} else {
		if err := unix.Renameat2(sourceParent, sourceBase, destinationParent, destinationBase, unix.RENAME_EXCHANGE); err != nil {
			return FileMoveOutput{}, fmt.Errorf("compare-and-replace move: %w", err)
		}
		rollback := func(cause error) (FileMoveOutput, error) {
			restoreErr := unix.Renameat2(sourceParent, sourceBase, destinationParent, destinationBase, unix.RENAME_EXCHANGE)
			if restoreErr != nil {
				return FileMoveOutput{}, fmt.Errorf("%w; move rollback failed: %v", cause, restoreErr)
			}
			_ = unix.Fsync(sourceParent)
			_ = unix.Fsync(destinationParent)
			return FileMoveOutput{}, cause
		}
		if err := e.verifyRegularAt(ctx, destinationParent, destinationBase, expectedSource, "moved source"); err != nil {
			return rollback(err)
		}
		if err := e.verifyRegularAt(ctx, sourceParent, sourceBase, expectedDestination, "replaced destination"); err != nil {
			return rollback(err)
		}
		if err := e.checkContext(ctx); err != nil {
			return rollback(err)
		}
		if err := unix.Unlinkat(sourceParent, sourceBase, 0); err != nil {
			return rollback(fmt.Errorf("remove replaced destination: %w", err))
		}
	}
	if err := unix.Fsync(sourceParent); err != nil {
		return FileMoveOutput{}, err
	}
	if destinationParent != sourceParent {
		if err := unix.Fsync(destinationParent); err != nil {
			return FileMoveOutput{}, err
		}
	}
	return FileMoveOutput{Source: sourceCanonical, Destination: destinationCanonical}, nil
}

func (e *Engine) secureAtomicWrite(path string, data []byte, fallbackMode os.FileMode) (string, error) {
	parentFD, base, canonical, err := e.secureParent(path, true)
	if err != nil {
		return "", err
	}
	defer unix.Close(parentFD)
	mode, err := secureExistingMode(parentFD, base, fallbackMode)
	if err != nil {
		return "", err
	}
	tmpName := ".chat-with-cli-write-" + protocol.NewID()
	fd, err := unix.Openat(parentFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), tmpName)
	cleanup := func() {
		_ = file.Close()
		_ = unix.Unlinkat(parentFD, tmpName, 0)
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", err
	}
	if err := unix.Renameat(parentFD, tmpName, parentFD, base); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return "", err
	}
	return canonical, nil
}

// secureAtomicWriteIfUnchanged commits a replacement only if the target still
// has the supplied content hash. On Linux, RENAME_EXCHANGE lets us validate
// the displaced inode after the kernel's atomic swap and restore it on a
// mismatch. This leaves an external update intact for the deterministic race
// case while avoiding a check-then-rename overwrite window.
func (e *Engine) secureAtomicWriteIfUnchanged(ctx context.Context, path string, data []byte, fallbackMode os.FileMode, expected string) (string, error) {
	expected, err := normalizedExpectedSHA256(expected)
	if err != nil || expected == "" {
		return "", err
	}
	parentFD, base, canonical, err := e.secureParent(path, true)
	if err != nil {
		return "", err
	}
	defer unix.Close(parentFD)
	mode, err := secureExistingMode(parentFD, base, fallbackMode)
	if err != nil {
		return "", err
	}
	tmpName := ".chat-with-cli-write-" + protocol.NewID()
	fd, err := unix.Openat(parentFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), tmpName)
	cleanup := func() {
		_ = file.Close()
		_ = unix.Unlinkat(parentFD, tmpName, 0)
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", err
	}
	if err := e.checkContext(ctx); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", err
	}
	if err := e.verifyRegularAt(ctx, parentFD, base, expected, "compare-and-replace target"); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", err
	}
	if hook := e.beforeFileCommit; hook != nil {
		e.beforeFileCommit = nil
		hook()
	}
	if err := e.checkContext(ctx); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", err
	}
	if err := unix.Renameat2(parentFD, tmpName, parentFD, base, unix.RENAME_EXCHANGE); err != nil {
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", fmt.Errorf("compare-and-replace file: %w", err)
	}
	oldTarget, verifyErr := e.openRegularAt(parentFD, tmpName, "displaced target")
	if verifyErr == nil {
		actual, hashErr := e.hashFileSHA256(oldTarget)
		_ = oldTarget.Close()
		if hashErr != nil {
			verifyErr = hashErr
		} else if actual != expected {
			verifyErr = verifySHA256(expected, actual)
		}
	}
	if verifyErr != nil {
		if restoreErr := unix.Renameat2(parentFD, tmpName, parentFD, base, unix.RENAME_EXCHANGE); restoreErr != nil {
			return "", fmt.Errorf("%w; compare-and-replace rollback failed: %v", verifyErr, restoreErr)
		}
		_ = unix.Fsync(parentFD)
		_ = unix.Unlinkat(parentFD, tmpName, 0)
		return "", verifyErr
	}
	if err := unix.Unlinkat(parentFD, tmpName, 0); err != nil {
		return "", fmt.Errorf("remove displaced target: %w", err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return "", err
	}
	return canonical, nil
}
