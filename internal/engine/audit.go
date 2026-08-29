package engine

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ifloppy/chat-with-cli/internal/protocol"
	"github.com/ifloppy/chat-with-cli/internal/securefile"
)

const maxAuditLogBytes int64 = 8 << 20

type auditLog struct {
	mu   sync.Mutex
	path string
}

func newAuditLog(stateDir string) (*auditLog, error) {
	dir := filepath.Join(stateDir, "audit")
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	return &auditLog{path: filepath.Join(dir, "events.jsonl")}, nil
}
func (a *auditLog) record(method string, started time.Time, callErr error) {
	event := AuditEvent{
		ID: protocol.NewID(), Time: started.UTC(), Method: method,
		DurationMS: time.Since(started).Milliseconds(), OK: callErr == nil,
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if info, err := os.Lstat(a.path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return
		}
		if err := securefile.CheckSingleLink(info, "audit log"); err != nil {
			return
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return
	}
	_ = a.rotateLocked(int64(len(data) + 1))
	file, err := securefile.Open(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600, "audit log")
	if err != nil {
		return
	}
	_ = file.Chmod(0o600)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || securefile.CheckSingleLink(info, "audit log") != nil {
		_ = file.Close()
		return
	}
	_, _ = file.Write(append(data, '\n'))
	_ = file.Close()
}

func (a *auditLog) rotateLocked(incoming int64) error {
	info, err := os.Lstat(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		if err != nil {
			return err
		}
		return errors.New("audit log must be a regular file")
	}
	if err := securefile.CheckSingleLink(info, "audit log"); err != nil {
		return err
	}
	if info.Size()+incoming <= maxAuditLogBytes {
		return err
	}
	rotated := a.path + ".1"
	_ = os.Remove(rotated)
	return os.Rename(a.path, rotated)
}

func (a *auditLog) recent(limit int) (AuditRecentOutput, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	events := make([]AuditEvent, 0, limit)
	for _, path := range []string{a.path + ".1", a.path} {
		part, err := readAuditFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return AuditRecentOutput{}, err
		}
		events = append(events, part...)
	}
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	return AuditRecentOutput{Events: events}, nil
}

func readAuditFile(path string) ([]AuditEvent, error) {
	file, err := securefile.Open(path, os.O_RDONLY, 0, "audit log")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("audit log must be a regular file")
	}
	if err := securefile.CheckSingleLink(info, "audit log"); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	events := make([]AuditEvent, 0, 128)
	for scanner.Scan() {
		var event AuditEvent
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Method != "" {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
