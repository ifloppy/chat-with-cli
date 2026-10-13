package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ifloppy/chat-with-cli/internal/releaseinstall"
)

// runInstallLocal is intentionally review-only without --apply. No existing
// executable is restarted by this command; even a successful replacement is
// inert until the operator explicitly restarts the service/process.
func runInstallLocal(args []string) error {
	fs := flag.NewFlagSet("install-local", flag.ContinueOnError)
	candidateFlag := fs.String("candidate", "", "path of locally built Chat With CLI executable")
	targetFlag := fs.String("binary", "", "installed binary to replace (default: running executable)")
	apply := fs.Bool("apply", false, "install the candidate and save checksum-verified rollback backup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*candidateFlag) == "" {
		return errors.New("--candidate is required")
	}
	candidate, err := normalizeExistingFile(*candidateFlag)
	if err != nil {
		return err
	}
	target, err := resolveUpdateBinary(*targetFlag)
	if err != nil {
		return err
	}
	if candidate == target {
		return errors.New("candidate and installed binary must be different paths")
	}
	bi, err := buildinfo.ReadFile(candidate)
	if err != nil {
		return fmt.Errorf("candidate is not a readable Go executable: %w", err)
	}
	if bi.Path != "github.com/ifloppy/chat-with-cli/cmd/chat-with-cli" {
		return fmt.Errorf("candidate module %q is not Chat With CLI", bi.Path)
	}
	if runtime.GOOS != "linux" {
		return errors.New("local binary installation currently supports Linux only")
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 128<<20 {
		return errors.New("candidate must be a regular non-symlink binary smaller than 128 MiB")
	}
	backup := target + ".previous"
	if err := releaseinstall.Preflight(target, backup); err != nil {
		return err
	}
	bytes, err := os.ReadFile(candidate)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bytes)
	fmt.Printf("Candidate: %s\nTarget: %s\nBackup: %s\nSHA256: %x\n", candidate, target, backup, sum)
	if !*apply {
		fmt.Println("Review only. No files changed; apply with --apply. Existing services/processes are never restarted.")
		return nil
	}
	if err := releaseinstall.Install(target, backup, bytes); err != nil {
		return err
	}
	fmt.Printf("Installed %s; restore with: chat-with-cli rollback --binary %s --apply\n", filepath.Base(target), target)
	fmt.Println("Active Agent and Relay processes were NOT restarted.")
	return nil
}
