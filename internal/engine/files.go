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
)

func (e *Engine) ReadFile(in FileReadInput) (FileReadOutput, error) {
	path, err := e.ResolvePath(in.Path)
	if err != nil {
		return FileReadOutput{}, err
	}
	if in.Offset < 0 {
		return FileReadOutput{}, errors.New("offset must be >= 0")
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 64 * 1024
	}
	if limit > e.cfg.MaxReadBytes {
		limit = e.cfg.MaxReadBytes
	}
	file, err := os.Open(path)
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
	if in.Offset > stat.Size() {
		in.Offset = stat.Size()
	}
	if _, err := file.Seek(in.Offset, io.SeekStart); err != nil {
		return FileReadOutput{}, err
	}
	buf := make([]byte, limit)
	n, readErr := file.Read(buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return FileReadOutput{}, readErr
	}
	next := in.Offset + int64(n)
	return FileReadOutput{
		Path: path, Content: string(buf[:n]), NextOffset: next, EOF: next >= stat.Size(),
	}, nil
}

func (e *Engine) WriteFile(in FileWriteInput) error {
	if !e.cfg.AllowFileWrite {
		return errors.New("filesystem write is disabled; start the agent with --allow-file-write")
	}
	path, err := e.ResolvePath(in.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(in.Mode)) {
	case "", "rewrite":
		return atomicWriteFile(path, []byte(in.Content))
	case "append":
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.WriteString(file, in.Content)
		return err
	default:
		return fmt.Errorf("unsupported write mode %q", in.Mode)
	}
}

func (e *Engine) ListFiles(in FileListInput) (FileListOutput, error) {
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
		if walkErr != nil {
			return walkErr
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
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			if path != root && shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if kind == "files" {
			if re.MatchString(path) {
				hits = append(hits, FileSearchHit{Path: path})
			}
		} else {
			fileHits := searchFileContent(path, re, max-len(hits))
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

func searchFileContent(path string, re *regexp.Regexp, remaining int) []FileSearchHit {
	if remaining <= 0 {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil
	}
	if isLikelyBinary(path) {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	hits := make([]FileSearchHit, 0, min(remaining, 8))
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if re.MatchString(text) {
			hits = append(hits, FileSearchHit{Path: path, Line: line, Text: compactLine(text, 500)})
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

func isLikelyBinary(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return true
	}
	defer file.Close()
	buf := make([]byte, 8192)
	n, _ := file.Read(buf)
	return bytes.IndexByte(buf[:n], 0) >= 0
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	return resolved, filepath.Join(dir, key+".md"), nil
}

func (e *Engine) WriteCheckpoint(in CheckpointWriteInput) error {
	if !e.cfg.AllowFileWrite {
		return errors.New("checkpoint writes are disabled; start the agent with --allow-file-write")
	}
	workspace, path, err := e.checkpointPath(in.Workspace)
	if err != nil {
		return err
	}
	content := "# chat-with-cli checkpoint\n\nWorkspace: `" + workspace + "`\n\n" + in.Content + "\n"
	return atomicWriteFileMode(path, []byte(content), 0o600)
}

func (e *Engine) ReadCheckpoint(in CheckpointReadInput) (CheckpointOutput, error) {
	workspace, path, err := e.checkpointPath(in.Workspace)
	if err != nil {
		return CheckpointOutput{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return CheckpointOutput{Workspace: workspace}, nil
	}
	if err != nil {
		return CheckpointOutput{}, err
	}
	return CheckpointOutput{Workspace: workspace, Content: string(data)}, nil
}

func (e *Engine) PatchFile(in FilePatchInput) (FilePatchOutput, error) {
	if !e.cfg.AllowFileWrite {
		return FilePatchOutput{}, errors.New("filesystem write is disabled; start the agent with --allow-file-write")
	}
	path, err := e.ResolvePath(in.Path)
	if err != nil {
		return FilePatchOutput{}, err
	}
	if in.OldText == "" {
		return FilePatchOutput{}, errors.New("old_text must not be empty")
	}
	expected := in.Expected
	if expected <= 0 {
		expected = 1
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return FilePatchOutput{}, err
	}
	count := bytes.Count(data, []byte(in.OldText))
	if count != expected {
		return FilePatchOutput{}, fmt.Errorf("expected %d exact matches, found %d", expected, count)
	}
	patched := bytes.Replace(data, []byte(in.OldText), []byte(in.NewText), expected)
	if err := atomicWriteFile(path, patched); err != nil {
		return FilePatchOutput{}, err
	}
	return FilePatchOutput{Path: path, Replacements: count}, nil
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
