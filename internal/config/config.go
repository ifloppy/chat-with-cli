package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Values is the intentionally small, dependency-free TOML subset used by the
// command line configuration files. It supports strings, booleans, integers,
// string arrays, comments, and [agent]/[relay] sections. Secrets are not
// represented by this file; use environment variables for secrets.
type Values map[string]string

func Load(path string) (Values, error) {
	data, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer data.Close()
	values := Values{}
	section := ""
	scanner := bufio.NewScanner(data)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(stripComment(scanner.Text()))
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			section = strings.TrimSpace(text[1 : len(text)-1])
			if section != "agent" && section != "relay" {
				return nil, fmt.Errorf("%s:%d: unsupported section %q", path, line, section)
			}
			continue
		}
		key, raw, ok := strings.Cut(text, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, line)
		}
		key = strings.TrimSpace(key)
		if strings.ContainsAny(key, " \t\r\n") {
			return nil, fmt.Errorf("%s:%d: invalid key %q", path, line, key)
		}
		if section != "" {
			key = section + "." + key
		}
		values[key] = strings.TrimSpace(raw)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func LoadOptional(path string) (Values, error) {
	if strings.TrimSpace(path) == "" {
		return Values{}, nil
	}
	values, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return Values{}, nil
	}
	return values, err
}

func (v Values) Raw(keys ...string) (string, bool) {
	for _, key := range keys {
		if raw, ok := v[key]; ok {
			return strings.TrimSpace(raw), true
		}
	}
	return "", false
}

func (v Values) String(defaultValue string, keys ...string) string {
	raw, ok := v.Raw(keys...)
	if !ok {
		return defaultValue
	}
	value, err := parseString(raw)
	if err != nil {
		return defaultValue
	}
	return value
}

func (v Values) Bool(defaultValue bool, keys ...string) bool {
	raw, ok := v.Raw(keys...)
	if !ok {
		return defaultValue
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return defaultValue
	}
	return value
}

func (v Values) Int(defaultValue int, keys ...string) int {
	raw, ok := v.Raw(keys...)
	if !ok {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return defaultValue
	}
	return value
}

func (v Values) Strings(keys ...string) []string {
	raw, ok := v.Raw(keys...)
	if !ok {
		return nil
	}
	raw = strings.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '[' || raw[len(raw)-1] != ']' {
		return nil
	}
	parts := splitArray(raw[1 : len(raw)-1])
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value, err := parseString(strings.TrimSpace(part))
		if err != nil {
			return nil
		}
		values = append(values, value)
	}
	return values
}

func Write(path string, values map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("configuration path must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lines := []string{"# chat-with-cli configuration; secrets belong in the environment, not this file", ""}
	for _, section := range []string{"relay", "agent"} {
		sectionValues := make(map[string]any)
		for key, value := range values {
			prefix := section + "."
			if strings.HasPrefix(key, prefix) {
				sectionValues[strings.TrimPrefix(key, prefix)] = value
			}
		}
		if len(sectionValues) == 0 {
			continue
		}
		lines = append(lines, "["+section+"]")
		keys := make([]string, 0, len(sectionValues))
		for key := range sectionValues {
			keys = append(keys, key)
		}
		sortStrings(keys)
		for _, key := range keys {
			lines = append(lines, key+" = "+formatValue(sectionValues[key]))
		}
		lines = append(lines, "")
	}
	data := []byte(strings.Join(lines, "\n"))
	tmp, err := os.CreateTemp(filepath.Dir(path), ".chat-with-cli-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
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

func parseString(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && ((raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'')) {
		if raw[0] == '\'' {
			return raw[1 : len(raw)-1], nil
		}
		return strconv.Unquote(raw)
	}
	if raw == "" || strings.ContainsAny(raw, "\r\n") {
		return "", errors.New("invalid string")
	}
	return raw, nil
}

func splitArray(raw string) []string {
	var parts []string
	start := 0
	quoted := byte(0)
	escaped := false
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if quoted != 0 {
			if escaped {
				escaped = false
			} else if ch == '\\' && quoted == '"' {
				escaped = true
			} else if ch == quoted {
				quoted = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quoted = ch
		} else if ch == ',' {
			parts = append(parts, raw[start:i])
			start = i + 1
		}
	}
	if strings.TrimSpace(raw[start:]) != "" {
		parts = append(parts, raw[start:])
	}
	return parts
}

func stripComment(line string) string {
	quoted := byte(0)
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if quoted != 0 {
			if escaped {
				escaped = false
			} else if ch == '\\' && quoted == '"' {
				escaped = true
			} else if ch == quoted {
				quoted = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			quoted = ch
		} else if ch == '#' {
			return line[:i]
		}
	}
	return line
}

func formatValue(value any) string {
	switch value := value.(type) {
	case string:
		return strconv.Quote(value)
	case bool:
		return strconv.FormatBool(value)
	case int:
		return strconv.Itoa(value)
	case []string:
		quoted := make([]string, len(value))
		for i, item := range value {
			quoted[i] = strconv.Quote(item)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	default:
		return strconv.Quote(fmt.Sprint(value))
	}
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
