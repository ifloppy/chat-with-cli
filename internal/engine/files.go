package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ifloppy/chat-with-cli/internal/securefile"
)

func normalizedExpectedSHA256(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	if len(value) != sha256.Size*2 {
		return "", errors.New("expected_sha256 must be a 64-character hexadecimal SHA-256")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("expected_sha256 must be a 64-character hexadecimal SHA-256")
	}
	return value, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func verifyExpectedSHA256(data []byte, expected string) error {
	expected, err := normalizedExpectedSHA256(expected)
	if err != nil || expected == "" {
		return err
	}
	return verifySHA256(expected, sha256Hex(data))
}

func verifySHA256(expected, actual string) error {
	if actual != expected {
		return fmt.Errorf("file changed since it was read: expected sha256 %s, found %s", expected, actual)
	}
	return nil
}

func formatByteLimit(limit int64) string {
	const (
		kiB = int64(1 << 10)
		miB = int64(1 << 20)
	)
	switch {
	case limit > 0 && limit%miB == 0:
		return fmt.Sprintf("%d MiB", limit/miB)
	case limit > 0 && limit%kiB == 0:
		return fmt.Sprintf("%d KiB", limit/kiB)
	default:
		return fmt.Sprintf("%d bytes", limit)
	}
}

func maximumFileSizeError(kind string, limit int64) error {
	return fmt.Errorf("file exceeds maximum %s size (%s)", kind, formatByteLimit(limit))
}

// hashFileSHA256 streams a complete regular file through sha256 instead of
// loading it into memory. The caller owns the file descriptor; its position
// is reset to the beginning so callers can seek to their requested range
// afterwards.
func (e *Engine) hashFileSHA256(file *os.File) (string, error) {
	stat, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() {
		return "", errors.New("path is not a regular file")
	}
	if stat.Size() > e.cfg.MaxHashBytes {
		return "", maximumFileSizeError("SHA-256 snapshot", e.cfg.MaxHashBytes)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hasher := sha256.New()
	readLimit := e.cfg.MaxHashBytes + 1
	if readLimit <= 0 || readLimit < e.cfg.MaxHashBytes {
		readLimit = e.cfg.MaxHashBytes
	}
	n, err := io.Copy(hasher, io.LimitReader(file, readLimit))
	if err != nil {
		return "", err
	}
	if n > e.cfg.MaxHashBytes {
		return "", maximumFileSizeError("SHA-256 snapshot", e.cfg.MaxHashBytes)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (e *Engine) verifyFileSHA256(path, expected string) error {
	expected, err := normalizedExpectedSHA256(expected)
	if err != nil || expected == "" {
		return err
	}
	file, _, err := e.secureOpenRead(path)
	if err != nil {
		return fmt.Errorf("verify expected_sha256: %w", err)
	}
	defer file.Close()
	actual, err := e.hashFileSHA256(file)
	if err != nil {
		return err
	}
	return verifySHA256(expected, actual)
}

func (e *Engine) ReadFile(in FileReadInput) (FileReadOutput, error) {
	return e.readFileContext(context.Background(), in)
}

func (e *Engine) readFileContext(ctx context.Context, in FileReadInput) (FileReadOutput, error) {
	if err := e.checkContext(ctx); err != nil {
		return FileReadOutput{}, err
	}
	if in.Offset < 0 {
		return FileReadOutput{}, errors.New("offset must be >= 0")
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 64 * 1024
	}
	if limit > e.cfg.MaxReadChunkBytes {
		limit = e.cfg.MaxReadChunkBytes
	}
	file, path, err := e.secureOpenRead(in.Path)
	if err != nil {
		return FileReadOutput{}, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return FileReadOutput{}, err
	}
	if !stat.Mode().IsRegular() {
		return FileReadOutput{}, errors.New("path is not a regular file")
	}
	if err := securefile.CheckSingleLink(stat, "file"); err != nil {
		return FileReadOutput{}, err
	}
	sha := ""
	if stat.Size() <= e.cfg.MaxHashBytes {
		sha, err = e.hashFileSHA256(file)
		if err != nil {
			return FileReadOutput{}, err
		}
	}
	if in.Offset > stat.Size() {
		in.Offset = stat.Size()
	}
	if _, err := file.Seek(in.Offset, io.SeekStart); err != nil {
		return FileReadOutput{}, err
	}
	if err := e.checkContext(ctx); err != nil {
		return FileReadOutput{}, err
	}
	buf := make([]byte, limit)
	n, readErr := file.Read(buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return FileReadOutput{}, readErr
	}
	if err := e.checkContext(ctx); err != nil {
		return FileReadOutput{}, err
	}
	next := in.Offset + int64(n)
	return FileReadOutput{
		Path: path, Content: e.redactText(string(buf[:n])), NextOffset: next, EOF: next >= stat.Size(),
		Size: stat.Size(), SHA256: sha,
	}, nil
}

func (e *Engine) WriteFile(in FileWriteInput) error {
	return e.writeFileContext(context.Background(), in)
}

func (e *Engine) writeFileContext(ctx context.Context, in FileWriteInput) error {
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	if !e.cfg.AllowFileWrite {
		return errors.New("filesystem write is disabled; start the agent with --allow-file-write")
	}
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	switch mode {
	case "", "rewrite":
		if strings.TrimSpace(in.ExpectedSHA256) == "" {
			file, _, err := e.secureOpenRead(in.Path)
			if err == nil {
				_ = file.Close()
				return errors.New("expected_sha256 is required when rewriting an existing file; call fs_read first")
			}
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if err := e.verifyFileSHA256(in.Path, in.ExpectedSHA256); err != nil {
			return err
		}
		if err := e.checkContext(ctx); err != nil {
			return err
		}
		var err error
		if strings.TrimSpace(in.ExpectedSHA256) == "" {
			_, err = e.secureAtomicWrite(in.Path, []byte(in.Content), 0o644)
		} else {
			_, err = e.secureAtomicWriteIfUnchanged(ctx, in.Path, []byte(in.Content), 0o644, in.ExpectedSHA256)
		}
		return err
	case "append", "append_unchecked":
		// The explicit mode and the explicit flag are equivalent opt-ins. The
		// mode is useful for clients that want the unsafe behavior to be visible
		// in the operation name; the flag keeps the escape hatch available to
		// clients that only model write modes.
		unchecked := mode == "append_unchecked" || in.UnsafeAllowUncheckedAppend
		file, _, openErr := e.secureOpenRead(in.Path)
		existing := openErr == nil
		if file != nil {
			_ = file.Close()
		}
		if openErr != nil && !errors.Is(openErr, os.ErrNotExist) {
			return openErr
		}
		if existing {
			if strings.TrimSpace(in.ExpectedSHA256) == "" && !unchecked {
				return errors.New("expected_sha256 is required when appending to an existing file; call fs_read first or explicitly enable unsafe_allow_unchecked_append")
			}
			if strings.TrimSpace(in.ExpectedSHA256) != "" {
				if err := e.verifyFileSHA256(in.Path, in.ExpectedSHA256); err != nil {
					return err
				}
			}
		}
		if err := e.checkContext(ctx); err != nil {
			return err
		}
		file, _, err := e.secureOpenAppend(in.Path)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := e.checkContext(ctx); err != nil {
			return err
		}
		_, err = io.WriteString(file, in.Content)
		return err
	default:
		return fmt.Errorf("unsupported write mode %q", in.Mode)
	}
}

func (e *Engine) ListFiles(in FileListInput) (FileListOutput, error) {
	return e.listFilesContext(context.Background(), in)
}

func (e *Engine) listFilesContext(ctx context.Context, in FileListInput) (FileListOutput, error) {
	if err := e.checkContext(ctx); err != nil {
		return FileListOutput{}, err
	}
	root, err := e.ResolvePath(in.Path)
	if err != nil {
		return FileListOutput{}, err
	}
	depth := in.Depth
	if depth <= 0 {
		depth = 1
	}
	if depth > 8 {
		depth = 8
	}
	entries := make([]FileEntry, 0, 128)
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if err := e.checkContext(ctx); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if path != root && e.isProtectedPath(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		level := strings.Count(rel, string(filepath.Separator)) + 1
		if level > depth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() && shouldSkipDir(d.Name()) {
			return filepath.SkipDir
		}
		entry := FileEntry{Path: path, Type: "file"}
		if d.IsDir() {
			entry.Type = "directory"
		} else if d.Type()&os.ModeSymlink != 0 {
			entry.Type = "symlink"
		}
		if info, err := d.Info(); err == nil {
			entry.Size = info.Size()
		}
		entries = append(entries, entry)
		return nil
	})
	return FileListOutput{Entries: entries}, err
}

func (e *Engine) SearchFiles(ctx context.Context, in FileSearchInput) (FileSearchOutput, error) {
	if err := e.checkContext(ctx); err != nil {
		return FileSearchOutput{}, err
	}
	root, err := e.ResolvePath(in.Path)
	if err != nil {
		return FileSearchOutput{}, err
	}
	re, err := regexp.Compile(in.Pattern)
	if err != nil {
		return FileSearchOutput{}, fmt.Errorf("invalid pattern: %w", err)
	}
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if kind == "" {
		kind = "content"
	}
	if kind != "content" && kind != "files" {
		return FileSearchOutput{}, fmt.Errorf("unsupported search kind %q", in.Kind)
	}
	max := in.MaxResults
	if max <= 0 {
		max = 100
	}
	if max > 1000 {
		max = 1000
	}

	hits := make([]FileSearchHit, 0, min(max, 100))
	truncated := false
	stop := errors.New("search result limit reached")
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if path != root && e.isProtectedPath(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err := e.checkContext(ctx); err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		// Content search never follows symlinks. Following a workspace symlink
		// here would let an allowed root expose arbitrary files outside it.
		if d.Type()&os.ModeSymlink != 0 {
			if kind == "files" && re.MatchString(path) {
				hits = append(hits, FileSearchHit{Path: path})
			}
			return nil
		}
		if kind == "files" {
			if re.MatchString(path) {
				hits = append(hits, FileSearchHit{Path: path})
			}
		} else {
			fileHits := e.searchFileContent(path, re, max-len(hits))
			hits = append(hits, fileHits...)
		}
		if len(hits) >= max {
			truncated = true
			return stop
		}
		return nil
	})
	if errors.Is(err, stop) {
		err = nil
	}
	return FileSearchOutput{Hits: hits, Truncated: truncated}, err
}

func (e *Engine) searchFileContent(path string, re *regexp.Regexp, remaining int) []FileSearchHit {
	if remaining <= 0 {
		return nil
	}
	file, _, err := e.secureOpenRead(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil
	}
	probe := make([]byte, 8192)
	n, _ := file.Read(probe)
	if bytes.IndexByte(probe[:n], 0) >= 0 {
		return nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil
	}

	hits := make([]FileSearchHit, 0, min(remaining, 8))
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if re.MatchString(text) {
			hits = append(hits, FileSearchHit{Path: path, Line: line, Text: e.redactText(compactLine(text, 500))})
			if len(hits) >= remaining {
				break
			}
		}
	}
	return hits
}

func compactLine(line string, max int) string {
	line = strings.TrimSpace(line)
	if len(line) <= max {
		return line
	}
	return line[:max-1] + "…"
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", ".venv", "__pycache__", ".cache":
		return true
	default:
		return false
	}
}

func (e *Engine) checkpointPath(workspace string) (string, string, error) {
	resolved, err := e.ResolvePath(workspace)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(resolved))
	key := hex.EncodeToString(sum[:16])
	dir := filepath.Join(e.cfg.StateDir, "checkpoints")
	if err := ensurePrivateDir(dir); err != nil {
		return "", "", err
	}
	return resolved, filepath.Join(dir, key+".md"), nil
}

func (e *Engine) WriteCheckpoint(in CheckpointWriteInput) error {
	return e.writeCheckpointContext(context.Background(), in)
}

func (e *Engine) writeCheckpointContext(ctx context.Context, in CheckpointWriteInput) error {
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	if !e.cfg.AllowFileWrite {
		return errors.New("checkpoint writes are disabled; start the agent with --allow-file-write")
	}
	workspace, path, err := e.checkpointPath(in.Workspace)
	if err != nil {
		return err
	}
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	content := "# chat-with-cli checkpoint\n\nWorkspace: `" + workspace + "`\n\n" + in.Content + "\n"
	return atomicWriteFileMode(path, []byte(content), 0o600)
}

func (e *Engine) ReadCheckpoint(in CheckpointReadInput) (CheckpointOutput, error) {
	return e.readCheckpointContext(context.Background(), in)
}

func (e *Engine) readCheckpointContext(ctx context.Context, in CheckpointReadInput) (CheckpointOutput, error) {
	if err := e.checkContext(ctx); err != nil {
		return CheckpointOutput{}, err
	}
	workspace, path, err := e.checkpointPath(in.Workspace)
	if err != nil {
		return CheckpointOutput{}, err
	}
	data, err := securefile.Read(path, "checkpoint")
	if errors.Is(err, os.ErrNotExist) {
		return CheckpointOutput{Workspace: workspace}, nil
	}
	if err != nil {
		return CheckpointOutput{}, err
	}
	if err := e.checkContext(ctx); err != nil {
		return CheckpointOutput{}, err
	}
	return CheckpointOutput{Workspace: workspace, Content: e.redactText(string(data))}, nil
}

func (e *Engine) PatchFile(in FilePatchInput) (FilePatchOutput, error) {
	return e.patchFileContext(context.Background(), in)
}

func (e *Engine) patchFileContext(ctx context.Context, in FilePatchInput) (FilePatchOutput, error) {
	if err := e.checkContext(ctx); err != nil {
		return FilePatchOutput{}, err
	}
	if !e.cfg.AllowFileWrite {
		return FilePatchOutput{}, errors.New("filesystem write is disabled; start the agent with --allow-file-write")
	}
	if in.OldText == "" {
		return FilePatchOutput{}, errors.New("old_text must not be empty")
	}
	if bytes.IndexByte([]byte(in.OldText), 0) >= 0 || bytes.IndexByte([]byte(in.NewText), 0) >= 0 {
		return FilePatchOutput{}, errors.New("fs_patch does not support binary text containing NUL bytes")
	}
	if !utf8.ValidString(in.OldText) || !utf8.ValidString(in.NewText) {
		return FilePatchOutput{}, errors.New("fs_patch supports UTF-8 text only; invalid UTF-8 is treated as binary")
	}
	if strings.TrimSpace(in.ExpectedSHA256) == "" {
		return FilePatchOutput{}, errors.New("expected_sha256 is required for fs_patch; call fs_read first")
	}
	expected := in.Expected
	if expected <= 0 {
		expected = 1
	}
	file, _, err := e.secureOpenRead(in.Path)
	if err != nil {
		return FilePatchOutput{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, e.cfg.MaxPatchBytes+1))
	_ = file.Close()
	if err != nil {
		return FilePatchOutput{}, err
	}
	if int64(len(data)) > e.cfg.MaxPatchBytes {
		return FilePatchOutput{}, maximumFileSizeError("patch", e.cfg.MaxPatchBytes)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return FilePatchOutput{}, errors.New("fs_patch does not support binary files (NUL byte found)")
	}
	if !utf8.Valid(data) {
		return FilePatchOutput{}, errors.New("fs_patch supports UTF-8 text only; binary or invalid UTF-8 files are rejected")
	}
	if err := verifyExpectedSHA256(data, in.ExpectedSHA256); err != nil {
		return FilePatchOutput{}, err
	}
	if err := e.checkContext(ctx); err != nil {
		return FilePatchOutput{}, err
	}
	count := bytes.Count(data, []byte(in.OldText))
	if count != expected {
		return FilePatchOutput{}, fmt.Errorf("expected %d exact matches, found %d", expected, count)
	}
	patched := bytes.Replace(data, []byte(in.OldText), []byte(in.NewText), expected)
	if err := e.checkContext(ctx); err != nil {
		return FilePatchOutput{}, err
	}
	writtenPath, err := e.secureAtomicWriteIfUnchanged(ctx, in.Path, patched, 0o644, in.ExpectedSHA256)
	if err != nil {
		return FilePatchOutput{}, err
	}
	return FilePatchOutput{Path: writtenPath, Replacements: count}, nil
}

func (e *Engine) DeleteFile(in FileDeleteInput) error {
	return e.deleteFileContext(context.Background(), in)
}

func (e *Engine) deleteFileContext(ctx context.Context, in FileDeleteInput) error {
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	if !e.cfg.AllowFileWrite {
		return errors.New("filesystem write is disabled; start the agent with --allow-file-write")
	}
	return e.secureDelete(ctx, in.Path, in.ExpectedSHA256, in.AllowEmptyDir)
}

func (e *Engine) MoveFile(in FileMoveInput) (FileMoveOutput, error) {
	return e.moveFileContext(context.Background(), in)
}

func (e *Engine) moveFileContext(ctx context.Context, in FileMoveInput) (FileMoveOutput, error) {
	if err := e.checkContext(ctx); err != nil {
		return FileMoveOutput{}, err
	}
	if !e.cfg.AllowFileWrite {
		return FileMoveOutput{}, errors.New("filesystem write is disabled; start the agent with --allow-file-write")
	}
	return e.secureMove(ctx, in)
}

func (e *Engine) MakeDirectory(in FileMkdirInput) error {
	return e.makeDirectoryContext(context.Background(), in)
}

// Mkdir is a short compatibility alias for callers that use the filesystem
// operation name directly.
func (e *Engine) Mkdir(in FileMkdirInput) error { return e.MakeDirectory(in) }

func (e *Engine) makeDirectoryContext(ctx context.Context, in FileMkdirInput) error {
	if err := e.checkContext(ctx); err != nil {
		return err
	}
	if !e.cfg.AllowFileWrite {
		return errors.New("filesystem write is disabled; start the agent with --allow-file-write")
	}
	return e.secureMkdir(ctx, in.Path)
}

func atomicWriteFile(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to replace a symlink")
		}
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular file")
		}
		if err := securefile.CheckSingleLink(info, "file"); err != nil {
			return err
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWriteFileMode(path, data, mode)
}

func atomicWriteFileMode(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to replace a symlink")
		}
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular file")
		}
		if err := securefile.CheckSingleLink(info, "file"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".chat-with-cli-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	_ = dir.Close()
	return err
}
