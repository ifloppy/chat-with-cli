package engine

import (
	"context"
	"testing"
)

func TestObserveScreenshotMode(t *testing.T) {
	for input, want := range map[string]string{"": "auto", "AUTO": "auto", "always": "always", "never": "never"} {
		got, err := observeScreenshotMode(input)
		if err != nil {
			t.Fatalf("mode %q: %v", input, err)
		}
		if got != want {
			t.Fatalf("mode %q: got %q want %q", input, got, want)
		}
	}
	if _, err := observeScreenshotMode("sometimes"); err == nil {
		t.Fatal("expected invalid screenshot mode to fail")
	}
}

func TestAutoObserveScreenshotDecision(t *testing.T) {
	if !shouldAutoObserveScreenshot(ComputerObserveInput{}, ComputerUIQueryOutput{}) {
		t.Fatal("empty semantic observation should request screenshot fallback")
	}
	ui := ComputerUIQueryOutput{Nodes: []ComputerUINode{{Name: "Build", Bounds: ComputerUIBounds{Width: 80, Height: 30}}}}
	if shouldAutoObserveScreenshot(ComputerObserveInput{}, ui) {
		t.Fatal("useful semantic UI should avoid screenshot transfer")
	}
}

func TestComputerObserveHonorsIndependentScreenPermission(t *testing.T) {
	eng, err := New(Config{Roots: []string{t.TempDir()}, AllowScreen: true, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	out, err := eng.ComputerObserve(context.Background(), ComputerObserveInput{Screenshot: "never"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Info.ScreenAllowed || out.Info.AccessibilityAllowed || out.Screenshot != nil {
		t.Fatalf("unexpected screen-only observation: %+v", out)
	}
}
