package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLargeTextFilesUseIndependentReadHashPatchAndRewriteLimits(t *testing.T) {
	root := t.TempDir()
	eng, err := New(Config{
		Roots:             []string{root},
		AllowFileWrite:    true,
		StateDir:          t.TempDir(),
		MaxReadChunkBytes: 64 * 1024,
		MaxHashBytes:      2 << 20,
		MaxPatchBytes:     2 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	const prefix = "const Value = 1\n"
	data := append([]byte(prefix), bytes.Repeat([]byte("x"), 1<<20-len(prefix))...)
	path := filepath.Join(root, "large.txt")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	read, err := eng.ReadFile(FileReadInput{Path: path, Offset: 0, Limit: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Content) != 64*1024 || read.Size != int64(len(data)) || read.SHA256 != sha256Hex(data) || read.EOF {
		// The first chunk is intentionally not EOF; keep the detailed values in
		// the failure so a regression in chunking or hashing is obvious.
		t.Fatalf("large fs_read result: content=%d size=%d sha=%q eof=%v", len(read.Content), read.Size, read.SHA256, read.EOF)
	}

	patchedData := bytes.Replace(data, []byte(prefix), []byte("const Value = 2\n"), 1)
	if _, err := eng.PatchFile(FilePatchInput{
		Path: path, OldText: prefix, NewText: "const Value = 2\n", ExpectedSHA256: read.SHA256,
	}); err != nil {
		t.Fatalf("1 MiB patch failed: %v", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, patchedData) {
		t.Fatalf("large patch changed unexpected bytes: got hash %s want %s", sha256Hex(actual), sha256Hex(patchedData))
	}

	read, err = eng.ReadFile(FileReadInput{Path: path, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	rewrittenData := bytes.Replace(actual, []byte("const Value = 2\n"), []byte("const Value = 3\n"), 1)
	if err := eng.WriteFile(FileWriteInput{
		Path: path, Content: string(rewrittenData), Mode: "rewrite", ExpectedSHA256: read.SHA256,
	}); err != nil {
		t.Fatalf("1 MiB rewrite failed: %v", err)
	}
	actual, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, rewrittenData) {
		t.Fatalf("large rewrite changed unexpected bytes: got hash %s want %s", sha256Hex(actual), sha256Hex(rewrittenData))
	}
}

func TestPatchLimitIsIndependentAndReportsAUsefulError(t *testing.T) {
	root := t.TempDir()
	eng, err := New(Config{
		Roots:             []string{root},
		AllowFileWrite:    true,
		StateDir:          t.TempDir(),
		MaxReadChunkBytes: 64 * 1024,
		MaxHashBytes:      2 << 20,
		MaxPatchBytes:     128 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	data := append([]byte("needle\n"), bytes.Repeat([]byte("x"), 256<<10)...)
	path := filepath.Join(root, "too-large-for-patch.txt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	read := readSnapshot(t, eng, path)
	if _, err := eng.PatchFile(FilePatchInput{Path: path, OldText: "needle\n", NewText: "changed\n", ExpectedSHA256: read.SHA256}); err == nil || !strings.Contains(err.Error(), "file exceeds maximum patch size (128 KiB)") {
		t.Fatalf("oversized patch did not fail clearly: %v", err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, data) {
		t.Fatal("oversized patch changed the file")
	}
}

func TestHashLimitMakesSnapshotsUnavailableWithoutChangingReadChunks(t *testing.T) {
	root := t.TempDir()
	eng, err := New(Config{
		Roots:             []string{root},
		AllowFileWrite:    true,
		StateDir:          t.TempDir(),
		MaxReadChunkBytes: 64 * 1024,
		MaxHashBytes:      64 << 10,
		MaxPatchBytes:     2 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	data := bytes.Repeat([]byte("large text\n"), 16<<10)
	path := filepath.Join(root, "too-large-for-hash.txt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := eng.ReadFile(FileReadInput{Path: path, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if read.SHA256 != "" || read.Size != int64(len(data)) || read.Content != string(data[:1]) {
		t.Fatalf("hash limit changed chunk semantics: %+v", read)
	}
	if err := eng.verifyFileSHA256(path, sha256Hex(data)); err == nil || !strings.Contains(err.Error(), "maximum SHA-256 snapshot size (64 KiB)") {
		t.Fatalf("hash limit did not produce a clear error: %v", err)
	}
	if _, err := eng.PatchFile(FilePatchInput{Path: path, OldText: "large", NewText: "small"}); err == nil || !strings.Contains(err.Error(), "expected_sha256 is required") {
		t.Fatalf("patch without an unavailable snapshot was accepted: %v", err)
	}
}

func TestTextPatchPreservesUTF8LineEndingsAndExactBytes(t *testing.T) {
	root := t.TempDir()
	eng := newFilesystemTestEngine(t, root)

	tests := []struct {
		name    string
		before  []byte
		oldText string
		newText string
		count   int
		want    []byte
	}{
		{
			name:    "utf8",
			before:  []byte("中文 日本語 🚀 e\u0301\nconst Beta = 20\n"),
			oldText: "const Beta = 20\n", newText: "const Beta = 21\n",
			want: []byte("中文 日本語 🚀 e\u0301\nconst Beta = 21\n"),
		},
		{
			name:    "crlf",
			before:  []byte("line1\r\nline2\r\nline3\r\n"),
			oldText: "line2\r\n", newText: "changed\r\n",
			want: []byte("line1\r\nchanged\r\nline3\r\n"),
		},
		{
			name:   "no-final-newline",
			before: []byte("abc"), oldText: "b", newText: "XYZ", want: []byte("aXYZc"),
		},
		{
			name:   "empty-replacement",
			before: []byte("before\nremove me\nafter\n"), oldText: "remove me\n", newText: "", want: []byte("before\nafter\n"),
		},
		{
			name:   "insertion",
			before: []byte("anchor\nend\n"), oldText: "anchor\n", newText: "anchor\ninserted 🚀\n", want: []byte("anchor\ninserted 🚀\nend\n"),
		},
		{
			name:   "multiple-exact-matches",
			before: []byte("alpha beta alpha"), oldText: "alpha", newText: "omega", count: 2, want: []byte("omega beta omega"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, test.name+".txt")
			if err := os.WriteFile(path, test.before, 0o600); err != nil {
				t.Fatal(err)
			}
			snapshot := readSnapshot(t, eng, path)
			_, err := eng.PatchFile(FilePatchInput{
				Path: path, OldText: test.oldText, NewText: test.newText,
				Expected: test.count, ExpectedSHA256: snapshot.SHA256,
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("got bytes %q want %q", got, test.want)
			}
		})
	}
}

func TestTextPatchHandlesLongLinesAndRejectsNULBinaryContent(t *testing.T) {
	root := t.TempDir()
	eng := newFilesystemTestEngine(t, root)

	longLine := append(bytes.Repeat([]byte("x"), 70<<10), []byte(" needle\nend")...)
	longPath := filepath.Join(root, "long-line.txt")
	if err := os.WriteFile(longPath, longLine, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := readSnapshot(t, eng, longPath)
	if _, err := eng.PatchFile(FilePatchInput{Path: longPath, OldText: " needle\n", NewText: " changed\n", ExpectedSHA256: snapshot.SHA256}); err != nil {
		t.Fatalf("long-line patch failed: %v", err)
	}
	wantLong := append(bytes.Repeat([]byte("x"), 70<<10), []byte(" changed\nend")...)
	got, err := os.ReadFile(longPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantLong) {
		t.Fatalf("long-line patch changed unexpected bytes")
	}

	binaryPath := filepath.Join(root, "binary.dat")
	binaryData := []byte{'a', 0, 'b', 'c'}
	if err := os.WriteFile(binaryPath, binaryData, 0o600); err != nil {
		t.Fatal(err)
	}
	binarySnapshot := readSnapshot(t, eng, binaryPath)
	if _, err := eng.PatchFile(FilePatchInput{Path: binaryPath, OldText: "a", NewText: "z", ExpectedSHA256: binarySnapshot.SHA256}); err == nil || !strings.Contains(err.Error(), "does not support binary") {
		t.Fatalf("binary patch was accepted: %v", err)
	}
	if _, err := eng.PatchFile(FilePatchInput{Path: binaryPath, OldText: "a\x00", NewText: "z", ExpectedSHA256: binarySnapshot.SHA256}); err == nil || !strings.Contains(err.Error(), "does not support binary") {
		t.Fatalf("NUL patch text was accepted: %v", err)
	}
	got, err = os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, binaryData) {
		t.Fatal("binary patch changed the file")
	}
}

func TestPatchCompareAndReplaceRejectsUpdateBeforeFinalCommit(t *testing.T) {
	root := t.TempDir()
	eng := newFilesystemTestEngine(t, root)
	path := filepath.Join(root, "race.go")
	original := []byte("package demo\n\nconst Value = 1\n")
	external := []byte("package demo\n\nconst Value = 99 // user edit\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := readSnapshot(t, eng, path)
	var hookErr error
	eng.beforeFileCommit = func() {
		hookErr = os.WriteFile(path, external, 0o600)
	}
	if _, err := eng.PatchFile(FilePatchInput{
		Path: path, OldText: "Value = 1", NewText: "Value = 2", ExpectedSHA256: snapshot.SHA256,
	}); err == nil || !strings.Contains(err.Error(), "file changed since it was read") {
		t.Fatalf("final compare-and-replace accepted a concurrent update: %v", err)
	}
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, external) {
		t.Fatalf("concurrent update was not preserved: got %q want %q", got, external)
	}
}

func TestAppendExistingFileRequiresFreshSnapshotUnlessExplicitlyUnchecked(t *testing.T) {
	root := t.TempDir()
	eng := newFilesystemTestEngine(t, root)
	path := filepath.Join(root, "append.log")
	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.WriteFile(FileWriteInput{Path: path, Content: "two\n", Mode: "append"}); err == nil || !strings.Contains(err.Error(), "expected_sha256 is required") {
		t.Fatalf("unchecked existing append was accepted: %v", err)
	}
	snapshot := readSnapshot(t, eng, path)
	if err := eng.WriteFile(FileWriteInput{Path: path, Content: "two\n", Mode: "append", ExpectedSHA256: snapshot.SHA256}); err != nil {
		t.Fatalf("fresh snapshot append failed: %v", err)
	}
	stale := snapshot
	if err := os.WriteFile(path, []byte("one\nexternal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := eng.WriteFile(FileWriteInput{Path: path, Content: "stale\n", Mode: "append", ExpectedSHA256: stale.SHA256}); err == nil || !strings.Contains(err.Error(), "file changed since it was read") {
		t.Fatalf("stale append was accepted: %v", err)
	}
	if err := eng.WriteFile(FileWriteInput{Path: path, Content: "unchecked\n", Mode: "append_unchecked", UnsafeAllowUncheckedAppend: true}); err != nil {
		t.Fatalf("explicit unchecked append failed: %v", err)
	}
	if err := eng.WriteFile(FileWriteInput{Path: path, Content: "mode-only\n", Mode: "append_unchecked"}); err != nil {
		t.Fatalf("explicit append_unchecked mode failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "one\nexternal\nunchecked\nmode-only\n" {
		t.Fatalf("append content=%q", data)
	}
}

func TestTextPatchRejectsInvalidUTF8(t *testing.T) {
	root := t.TempDir()
	eng := newFilesystemTestEngine(t, root)
	path := filepath.Join(root, "invalid-utf8.bin")
	data := []byte{'a', 0xff, 'b'}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := readSnapshot(t, eng, path)
	if _, err := eng.PatchFile(FilePatchInput{Path: path, OldText: "a", NewText: "z", ExpectedSHA256: snapshot.SHA256}); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("invalid UTF-8 patch was accepted: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("invalid UTF-8 patch changed the file: %v", got)
	}
}
