//go:build linux

package execsandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLandlockReadOnlyBlocksWrites(t *testing.T) {
	if os.Getenv("CWC_LANDLOCK_TEST_HELPER") == "1" {
		root := os.Getenv("CWC_LANDLOCK_TEST_ROOT")
		outside := os.Getenv("CWC_LANDLOCK_TEST_OUTSIDE")
		if err := Apply([]string{root}, false, ""); err != nil {
			os.Exit(2)
		}
		insideErr := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("denied"), 0o600)
		outsideErr := os.WriteFile(outside, []byte("denied"), 0o600)
		if insideErr == nil || outsideErr == nil {
			os.Exit(3)
		}
		os.Exit(0)
	}

	if _, _, _, err := landlockAccessRights(); err != nil {
		t.Skipf("Landlock unavailable on test host: %v", err)
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside.txt")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockReadOnlyBlocksWrites$")
	cmd.Env = append(os.Environ(),
		"CWC_LANDLOCK_TEST_HELPER=1",
		"CWC_LANDLOCK_TEST_ROOT="+root,
		"CWC_LANDLOCK_TEST_OUTSIDE="+outside,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Landlock helper failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only sandbox wrote outside root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "inside.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only sandbox wrote inside root: %v", err)
	}
}

func TestLandlockWriteModeDoesNotEscapeRoot(t *testing.T) {
	if os.Getenv("CWC_LANDLOCK_WRITE_TEST_HELPER") == "1" {
		root := os.Getenv("CWC_LANDLOCK_TEST_ROOT")
		tempDir := os.Getenv("CWC_LANDLOCK_TEST_TEMP")
		outside := os.Getenv("CWC_LANDLOCK_TEST_OUTSIDE")
		if err := Apply([]string{root}, true, tempDir); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("allowed"), 0o600); err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(filepath.Join(tempDir, "temp.txt"), []byte("allowed-temp"), 0o600); err != nil {
			os.Exit(4)
		}
		if err := os.WriteFile(outside, []byte("denied"), 0o600); err == nil {
			os.Exit(5)
		}
		os.Exit(0)
	}
	if _, _, _, err := landlockAccessRights(); err != nil {
		t.Skipf("Landlock unavailable on test host: %v", err)
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	tempDir := filepath.Join(base, "private-tmp")
	outside := filepath.Join(base, "outside.txt")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockWriteModeDoesNotEscapeRoot$")
	cmd.Env = append(os.Environ(),
		"CWC_LANDLOCK_WRITE_TEST_HELPER=1",
		"CWC_LANDLOCK_TEST_ROOT="+root,
		"CWC_LANDLOCK_TEST_TEMP="+tempDir,
		"CWC_LANDLOCK_TEST_OUTSIDE="+outside,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Landlock write helper failed: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(root, "inside.txt"))
	if err != nil || string(data) != "allowed" {
		t.Fatalf("write-enabled sandbox could not write inside root: %v %q", err, data)
	}
	tempData, err := os.ReadFile(filepath.Join(tempDir, "temp.txt"))
	if err != nil || string(tempData) != "allowed-temp" {
		t.Fatalf("write-enabled sandbox could not use private temp dir: %v %q", err, tempData)
	}
	if _, err := os.Stat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("write-enabled sandbox escaped root: %v", err)
	}
}
