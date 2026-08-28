package engine

import (
	"context"
	"image/color"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestUIRefRoundTrip(t *testing.T) {
	want := atspiRef{Bus: ":1.42", Path: dbus.ObjectPath("/org/a11y/atspi/accessible/123")}
	encoded := encodeUIRef(want)
	got, err := decodeUIRef(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip mismatch: got=%+v want=%+v", got, want)
	}
	if _, err := decodeUIRef("not/a/ref"); err == nil {
		t.Fatal("expected malformed ref to fail")
	}
}

func TestATSPIReducedStateNames(t *testing.T) {
	cases := map[uint32]string{1: "active", 8: "enabled", 12: "focused", 25: "showing", 30: "visible", 31: "manages_descendants", 43: "read_only"}
	for value, want := range cases {
		if got := atspiStateName(value); got != want {
			t.Fatalf("state %d: got %q want %q", value, got, want)
		}
	}
}

func TestKWinBGRAToRGBA(t *testing.T) {
	// Two pixels plus four bytes of stride padding.
	raw := []byte{3, 2, 1, 255, 30, 20, 10, 255, 9, 9, 9, 9}
	img := kwinBGRAToRGBA(raw, 2, 1, 12)
	if got := img.RGBAAt(0, 0); got != (color.RGBA{R: 1, G: 2, B: 3, A: 255}) {
		t.Fatalf("first pixel=%+v", got)
	}
	if got := img.RGBAAt(1, 0); got != (color.RGBA{R: 10, G: 20, B: 30, A: 255}) {
		t.Fatalf("second pixel=%+v", got)
	}
}

func TestUIInspectionRequiresAccessibilityPermission(t *testing.T) {
	eng := testEngine(t, false)
	if _, err := eng.ComputerUITree(context.Background(), ComputerUITreeInput{}); err == nil {
		t.Fatal("UI tree should require accessibility permission")
	}
	if _, err := eng.ComputerUIAction(context.Background(), ComputerUIActionInput{Ref: "bad"}); err == nil {
		t.Fatal("semantic action should require computer control")
	}
}

func TestAccessibilityAndScreenPermissionsAreIndependent(t *testing.T) {
	root := t.TempDir()
	accessOnly, err := New(Config{Roots: []string{root}, AllowAccessibility: true, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer accessOnly.Close()
	if info := accessOnly.ComputerInfo(); !info.AccessibilityAllowed || info.ScreenAllowed {
		t.Fatalf("unexpected accessibility-only capabilities: %+v", info)
	}
	screenOnly, err := New(Config{Roots: []string{root}, AllowScreen: true, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer screenOnly.Close()
	if info := screenOnly.ComputerInfo(); info.AccessibilityAllowed || !info.ScreenAllowed {
		t.Fatalf("unexpected screen-only capabilities: %+v", info)
	}
}

func TestKWinPermissionErrorDetection(t *testing.T) {
	if !isKWinPermissionError(&dbus.Error{Name: "org.test", Body: []any{"The process is not authorized to take a screenshot"}}) {
		t.Fatal("expected permission denial to be recognized")
	}
}

func TestUIInvokeRequiresSpecificSelector(t *testing.T) {
	root := t.TempDir()
	eng, err := New(Config{
		Roots: []string{root}, AllowScreen: true, AllowAccessibility: true, AllowComputerControl: true,
		StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	out, err := eng.ComputerUIInvoke(context.Background(), ComputerUIInvokeInput{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "invalid_selector" {
		t.Fatalf("status=%q output=%+v", out.Status, out)
	}
}

func TestInvokeDefaultStatesAreSafe(t *testing.T) {
	states := defaultInvokeStates(nil)
	want := []string{"showing", "visible", "enabled"}
	for i := range want {
		if states[i] != want[i] {
			t.Fatalf("states=%v", states)
		}
	}
}

func TestWalkerMatchLimitIsBounded(t *testing.T) {
	filtered := &atspiWalker{maxNodes: 400, maxResults: 80, requiredStates: map[string]bool{"visible": true}, matches: make([]ComputerUINode, 80)}
	if !filtered.matchLimitReached() {
		t.Fatal("filtered walker should stop at result cap")
	}
	tree := &atspiWalker{maxNodes: 80, maxResults: 80, matches: make([]ComputerUINode, 80)}
	if tree.matchLimitReached() {
		t.Fatal("unfiltered tree should be bounded by node count rather than match cap")
	}
}

func TestUniqueSelectorValidation(t *testing.T) {
	_, _, _, invalid := normalizeUniqueUISelector(uniqueUISelector{})
	if invalid.Status != "invalid_selector" {
		t.Fatalf("unexpected status %q", invalid.Status)
	}
	_, _, _, invalid = normalizeUniqueUISelector(uniqueUISelector{Query: "Save", TimeoutMS: 30001})
	if invalid.Status != "invalid_timeout" {
		t.Fatalf("unexpected timeout status %q", invalid.Status)
	}
	_, _, _, invalid = normalizeUniqueUISelector(uniqueUISelector{Query: "Save", TimeoutMS: 1000, PollMS: 50})
	if invalid.Status != "invalid_poll_interval" {
		t.Fatalf("unexpected poll status %q", invalid.Status)
	}
}

func TestUISetTextRejectsNULBeforeDesktopAccess(t *testing.T) {
	eng, err := New(Config{
		Roots: []string{t.TempDir()}, AllowScreen: true, AllowAccessibility: true, AllowComputerControl: true,
		StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	out, err := eng.ComputerUISetText(context.Background(), ComputerUISetTextInput{Query: "field", Text: "bad\x00value"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "invalid_text" {
		t.Fatalf("status=%q output=%+v", out.Status, out)
	}
}

func TestUIGetTextRejectsOversizedReadBeforeDesktopAccess(t *testing.T) {
	eng, err := New(Config{
		Roots: []string{t.TempDir()}, AllowScreen: true, AllowAccessibility: true,
		StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	out, err := eng.ComputerUIGetText(context.Background(), ComputerUIGetTextInput{
		Query: "field", MaxCharacters: 65537,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "invalid_limit" {
		t.Fatalf("status=%q output=%+v", out.Status, out)
	}
}
