package mcpgateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

const maxRegistryBytes = 1 << 20

var validID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// ServerConfig describes one explicitly configured downstream MCP server.
// The gateway never executes commands read from another client's configuration
// unless the user imports and enables them here.
type ServerConfig struct {
	Transport string   `json:"transport"`
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
	URL       string   `json:"url,omitempty"`
	Enabled   bool     `json:"enabled"`
	Expose    bool     `json:"expose"`
}

type Registry struct {
	Version int                     `json:"version"`
	Servers map[string]ServerConfig `json:"servers"`
}

func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "mcp.json"
	}
	return filepath.Join(dir, "chat-with-cli", "mcp.json")
}

func (r Registry) Validate() error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported MCP registry version %d", r.Version)
	}
	for id, cfg := range r.Servers {
		if !validID.MatchString(id) {
			return fmt.Errorf("invalid MCP server ID %q", id)
		}
		switch cfg.Transport {
		case "stdio":
			if cfg.Command == "" || cfg.URL != "" {
				return fmt.Errorf("%s: stdio requires command and no URL", id)
			}
		case "streamable-http":
			if cfg.URL == "" || cfg.Command != "" || len(cfg.Args) != 0 {
				return fmt.Errorf("%s: HTTP requires URL and no command", id)
			}
			if err := checkHTTPURL(cfg.URL); err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
		default:
			return fmt.Errorf("%s: unsupported transport %q", id, cfg.Transport)
		}
	}
	return nil
}

func Load(path string) (Registry, error) {
	r := Registry{Version: 1, Servers: make(map[string]ServerConfig)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxRegistryBytes {
		return r, errors.New("MCP registry must be a regular non-symlink file smaller than 1 MiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("decode MCP registry: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return r, errors.New("MCP registry contains trailing JSON or invalid data")
	}
	if err := r.Validate(); err != nil {
		return r, err
	}
	if r.Servers == nil {
		r.Servers = make(map[string]ServerConfig)
	}
	return r, nil
}

func Save(path string, r Registry) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("MCP registry must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".mcp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func ServerIDs(r Registry) []string {
	ids := make([]string, 0, len(r.Servers))
	for id := range r.Servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
