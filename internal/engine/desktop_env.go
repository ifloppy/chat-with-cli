package engine

import (
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
)

func currentEnvMap() map[string]string {
	out := make(map[string]string, len(os.Environ()))
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok && key != "" {
			out[key] = value
		}
	}
	return out
}

func desktopEnvMap() map[string]string {
	env := currentEnvMap()
	runtimeDir := strings.TrimSpace(env["XDG_RUNTIME_DIR"])
	if runtimeDir == "" {
		if current, err := user.Current(); err == nil && current.Uid != "" {
			candidate := filepath.Join("/run/user", current.Uid)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				runtimeDir = candidate
				env["XDG_RUNTIME_DIR"] = candidate
			}
		}
	}
	if runtimeDir != "" {
		if env["DBUS_SESSION_BUS_ADDRESS"] == "" {
			bus := filepath.Join(runtimeDir, "bus")
			if info, err := os.Stat(bus); err == nil && info.Mode()&os.ModeSocket != 0 {
				env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + bus
			}
		}
		if env["WAYLAND_DISPLAY"] == "" {
			matches, _ := filepath.Glob(filepath.Join(runtimeDir, "wayland-*"))
			sort.Strings(matches)
			for _, match := range matches {
				if strings.HasSuffix(match, ".lock") {
					continue
				}
				if info, err := os.Stat(match); err == nil && info.Mode()&os.ModeSocket != 0 {
					env["WAYLAND_DISPLAY"] = filepath.Base(match)
					break
				}
			}
		}
	}
	if env["WAYLAND_DISPLAY"] != "" {
		if env["XDG_SESSION_TYPE"] == "" {
			env["XDG_SESSION_TYPE"] = "wayland"
		}
		if env["QT_QPA_PLATFORM"] == "" {
			env["QT_QPA_PLATFORM"] = "wayland"
		}
	}
	upperLocale := strings.ToUpper(env["LANG"])
	if upperLocale == "" || !strings.Contains(upperLocale, "UTF") {
		env["LANG"] = "C.utf8"
	}
	return env
}

func desktopCommandEnv() []string {
	env := desktopEnvMap()
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}

func desktopEnvValue(key string) string {
	return desktopEnvMap()[key]
}
