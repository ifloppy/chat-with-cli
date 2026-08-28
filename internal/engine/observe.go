package engine

import (
	"context"
	"fmt"
	"strings"
)

func observeScreenshotMode(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return "auto", nil
	case "always", "never":
		return strings.ToLower(strings.TrimSpace(value)), nil
	default:
		return "", fmt.Errorf("screenshot must be auto, always, or never, got %q", value)
	}
}

func defaultObserveStates(states []string) []string {
	if len(states) > 0 {
		return states
	}
	return []string{"showing", "visible"}
}
func shouldAutoObserveScreenshot(in ComputerObserveInput, ui ComputerUIQueryOutput) bool {
	if len(ui.Nodes) == 0 {
		return true
	}
	if strings.TrimSpace(in.Query) != "" || strings.TrimSpace(in.Role) != "" || strings.TrimSpace(in.AppName) != "" {
		return false
	}
	for _, node := range ui.Nodes {
		if strings.TrimSpace(node.Name) != "" && (len(node.Actions) > 0 || node.Bounds.Width > 0 || node.Bounds.Height > 0) {
			return false
		}
	}
	return true
}

func (e *Engine) ComputerObserve(ctx context.Context, in ComputerObserveInput) (ComputerObserveOutput, error) {
	mode, err := observeScreenshotMode(in.Screenshot)
	if err != nil {
		return ComputerObserveOutput{}, err
	}
	maxResults := in.MaxResults
	if maxResults <= 0 {
		maxResults = 80
	}
	if maxResults > 200 {
		maxResults = 200
	}
	ui, err := e.ComputerUIFind(ctx, ComputerUIFindInput{
		AppName: in.AppName, Query: in.Query, Role: in.Role,
		RequiredStates: defaultObserveStates(in.RequiredStates), MaxDepth: in.MaxDepth,
		MaxNodes: in.MaxNodes, MaxResults: maxResults,
	})
	if err != nil {
		return ComputerObserveOutput{}, err
	}
	out := ComputerObserveOutput{Info: e.ComputerInfo(), UI: ui}
	capture := mode == "always" || (mode == "auto" && shouldAutoObserveScreenshot(in, ui))
	if !capture {
		return out, nil
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "jpeg"
	}
	quality := in.JPEGQuality
	if quality <= 0 && (format == "jpeg" || format == "jpg") {
		quality = 70
	}
	shot, err := e.Screenshot(ctx, ComputerScreenshotInput{Format: format, JPEGQuality: quality})
	if err != nil {
		return ComputerObserveOutput{}, err
	}
	out.Screenshot = &shot
	if mode == "always" {
		out.ScreenshotReason = "requested"
	} else {
		out.ScreenshotReason = "semantic_ui_insufficient"
	}
	return out, nil
}
