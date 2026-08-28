package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestNormalizeComputerPersistMode(t *testing.T) {
	cases := map[string]string{"": "process", "PROCESS": "process", "none": "none", "persistent": "persistent"}
	for input, want := range cases {
		got, err := normalizeComputerPersistMode(input)
		if err != nil || got != want {
			t.Fatalf("normalize %q = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := normalizeComputerPersistMode("forever"); err == nil {
		t.Fatal("expected invalid persist mode to fail")
	}
}

func TestPortalPairAndCoordinateScaling(t *testing.T) {
	v := dbus.MakeVariant(struct{ A, B int32 }{1707, 1067})
	w, h, ok := portalPair(v)
	if !ok || w != 1707 || h != 1067 {
		t.Fatalf("portalPair = %d,%d,%v", w, h, ok)
	}

	x, y := scalePortalPoint(1280, 800, 2560, 1600, 1707, 1067)
	if x < 853 || x > 854 || y < 533 || y > 534 {
		t.Fatalf("scaled midpoint = %.2f,%.2f", x, y)
	}
	x, y = scalePortalPoint(-10, 9999, 2560, 1600, 1707, 1067)
	if x != 0 || y != 1066 {
		t.Fatalf("clamped point = %.2f,%.2f", x, y)
	}
}

func TestPersistentPortalTokenStored0600(t *testing.T) {
	eng := testEngine(t, false)
	eng.cfg.ComputerPersistMode = "persistent"
	eng.portalMu.Lock()
	if err := eng.savePortalRestoreTokenLocked("one-time-token"); err != nil {
		eng.portalMu.Unlock()
		t.Fatal(err)
	}
	eng.portalMu.Unlock()

	path := filepath.Join(eng.cfg.StateDir, "computer", "portal-restore-token")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("restore token mode = %o", info.Mode().Perm())
	}

	eng.portalMu.Lock()
	eng.portalRestoreToken = ""
	eng.portalTokenLoaded = false
	eng.loadPortalRestoreTokenLocked()
	loaded := eng.portalRestoreToken
	eng.clearPortalRestoreTokenLocked()
	eng.portalMu.Unlock()
	if loaded != "one-time-token" {
		t.Fatalf("loaded restore token = %q", loaded)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("restore token should be removed after single-use clear, err=%v", err)
	}
}

func TestPortalKeysyms(t *testing.T) {
	if sym, ok := namedKeysym("Ctrl"); !ok || sym != 0xffe3 {
		t.Fatalf("Ctrl keysym = %#x, %v", sym, ok)
	}
	if sym, ok := namedKeysym("F12"); !ok || sym != 0xffc9 {
		t.Fatalf("F12 keysym = %#x, %v", sym, ok)
	}
	if got := runeKeysym('中'); got != 0x01004e2d {
		t.Fatalf("Unicode keysym = %#x", got)
	}
}
