package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Keep enough headroom for base64 + JSON inside the 32 MiB Agent/Relay WebSocket limit.
const maxScreenshotBytes = 20 * 1024 * 1024

func (e *Engine) ComputerInfo() ComputerInfoOutput {
	backend := detectScreenshotBackend()
	e.computerMu.Lock()
	kwinDisabled := e.kwinDBusDisabled
	e.computerMu.Unlock()
	if !kwinDisabled && kwinScreenshotServiceAvailable() {
		if backend != "" {
			backend = "kwin-dbus+" + backend
		} else {
			backend = "kwin-dbus"
		}
	}
	accessibility := ""
	if atspiAvailable() {
		accessibility = "at-spi2"
	}
	portalActive := false
	if e.portalMu.TryLock() {
		portalActive = e.portal != nil && !e.portal.isClosed()
		e.portalMu.Unlock()
	}
	return ComputerInfoOutput{
		ScreenAllowed: e.cfg.AllowScreen, ControlAllowed: e.cfg.AllowComputerControl,
		SessionType: sessionType(), Desktop: desktopEnvValue("XDG_CURRENT_DESKTOP"),
		ScreenshotBackend: backend, InputBackend: detectInputBackend(), AccessibilityBackend: accessibility,
		ComputerPersistMode: e.cfg.ComputerPersistMode, PortalSessionActive: portalActive,
	}
}

func sessionType() string {
	env := desktopEnvMap()
	if value := strings.TrimSpace(env["XDG_SESSION_TYPE"]); value != "" {
		return value
	}
	if env["WAYLAND_DISPLAY"] != "" {
		return "wayland"
	}
	if env["DISPLAY"] != "" {
		return "x11"
	}
	return "unknown"
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func detectScreenshotBackend() string {
	for _, name := range []string{"spectacle", "grim", "gnome-screenshot"} {
		if commandExists(name) {
			return name
		}
	}
	if desktopEnvValue("DISPLAY") != "" && commandExists("import") {
		return "imagemagick"
	}
	return ""
}

func detectInputBackend() string {
	if sessionType() == "wayland" && portalRemoteDesktopAvailable() {
		return "xdg-desktop-portal"
	}
	if commandExists("wdotool") {
		return "wdotool"
	}
	if sessionType() == "x11" && commandExists("xdotool") {
		return "xdotool"
	}
	return ""
}

func (e *Engine) Screenshot(ctx context.Context, in ComputerScreenshotInput) (ComputerScreenshotOutput, error) {
	if !e.cfg.AllowScreen {
		return ComputerScreenshotOutput{}, errors.New("screen capture is disabled; start with --allow-screen or --allow-computer-use")
	}
	if shot, ok := e.tryKWinScreenshot(ctx, in); ok {
		return e.rememberScreenshot(shot), nil
	}
	backend := detectScreenshotBackend()
	if backend == "" {
		return ComputerScreenshotOutput{}, errors.New("no supported screenshot backend found")
	}
	dir := filepath.Join(e.cfg.StateDir, "computer")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ComputerScreenshotOutput{}, err
	}
	file, err := os.CreateTemp(dir, "screenshot-*.png")
	if err != nil {
		return ComputerScreenshotOutput{}, err
	}
	path := file.Name()
	_ = file.Close()
	defer os.Remove(path)

	captureCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	switch backend {
	case "spectacle":
		cmd = exec.CommandContext(captureCtx, "spectacle", "-b", "-n", "-o", path)
	case "grim":
		cmd = exec.CommandContext(captureCtx, "grim", path)
	case "gnome-screenshot":
		cmd = exec.CommandContext(captureCtx, "gnome-screenshot", "-f", path)
	case "imagemagick":
		cmd = exec.CommandContext(captureCtx, "import", "-window", "root", path)
	default:
		return ComputerScreenshotOutput{}, fmt.Errorf("unsupported screenshot backend %q", backend)
	}
	cmd.Env = desktopCommandEnv()
	if output, err := cmd.CombinedOutput(); err != nil {
		return ComputerScreenshotOutput{}, fmt.Errorf("%s screenshot failed: %w: %s", backend, err, strings.TrimSpace(string(output)))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ComputerScreenshotOutput{}, err
	}
	if len(data) == 0 {
		return ComputerScreenshotOutput{}, errors.New("screenshot backend produced an empty image")
	}
	if len(data) > maxScreenshotBytes {
		return ComputerScreenshotOutput{}, fmt.Errorf("screenshot is too large: %d bytes", len(data))
	}

	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return ComputerScreenshotOutput{}, fmt.Errorf("decode screenshot metadata: %w", err)
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" || format == "png" {
		return e.rememberScreenshot(ComputerScreenshotOutput{MIMEType: "image/png", Data: data, Width: cfg.Width, Height: cfg.Height}), nil
	}
	if format != "jpeg" && format != "jpg" {
		return ComputerScreenshotOutput{}, fmt.Errorf("unsupported screenshot format %q", in.Format)
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return ComputerScreenshotOutput{}, fmt.Errorf("decode screenshot: %w", err)
	}
	quality := in.JPEGQuality
	if quality <= 0 {
		quality = 85
	}
	if quality < 1 || quality > 100 {
		return ComputerScreenshotOutput{}, errors.New("jpeg_quality must be between 1 and 100")
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: quality}); err != nil {
		return ComputerScreenshotOutput{}, err
	}
	return e.rememberScreenshot(ComputerScreenshotOutput{MIMEType: "image/jpeg", Data: out.Bytes(), Width: cfg.Width, Height: cfg.Height}), nil
}

func (e *Engine) rememberScreenshot(out ComputerScreenshotOutput) ComputerScreenshotOutput {
	e.computerMu.Lock()
	e.lastScreenshotWidth, e.lastScreenshotHeight = out.Width, out.Height
	e.computerMu.Unlock()
	return out
}

func (e *Engine) requireComputerControl() (string, error) {
	if !e.cfg.AllowComputerControl {
		return "", errors.New("computer control is disabled; start with --allow-computer-use")
	}
	backend := detectInputBackend()
	if backend == "" {
		return "", errors.New("no supported input backend found; a RemoteDesktop portal is preferred on Wayland, with wdotool/xdotool as fallbacks")
	}
	return backend, nil
}

func runInputCommand(ctx context.Context, name string, args ...string) error {
	inputCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(inputCtx, name, args...)
	cmd.Env = desktopCommandEnv()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func mouseButton(button string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(button)) {
	case "", "left", "1":
		return "1", nil
	case "middle", "2":
		return "2", nil
	case "right", "3":
		return "3", nil
	case "back", "8":
		return "8", nil
	case "forward", "9":
		return "9", nil
	default:
		return "", fmt.Errorf("unsupported mouse button %q", button)
	}
}

func (e *Engine) ComputerMove(ctx context.Context, in ComputerMoveInput) error {
	backend, err := e.requireComputerControl()
	if err != nil {
		return err
	}
	x, y := strconv.Itoa(in.X), strconv.Itoa(in.Y)
	switch backend {
	case "xdg-desktop-portal":
		return e.portalMove(ctx, in)
	case "wdotool":
		return runInputCommand(ctx, "wdotool", "mousemove", x, y)
	case "xdotool":
		return runInputCommand(ctx, "xdotool", "mousemove", "--sync", x, y)
	default:
		return fmt.Errorf("unsupported input backend %q", backend)
	}
}

func (e *Engine) ComputerClick(ctx context.Context, in ComputerClickInput) error {
	backend, err := e.requireComputerControl()
	if err != nil {
		return err
	}
	button, err := mouseButton(in.Button)
	if err != nil {
		return err
	}
	clicks := in.Clicks
	if clicks <= 0 {
		clicks = 1
	}
	if clicks > 5 {
		return errors.New("clicks must be between 1 and 5")
	}

	switch backend {
	case "xdg-desktop-portal":
		return e.portalClick(ctx, in)
	case "wdotool":
		for range clicks {
			if err := runInputCommand(ctx, "wdotool", "click", button); err != nil {
				return err
			}
		}
		return nil
	case "xdotool":
		return runInputCommand(ctx, "xdotool", "click", "--repeat", strconv.Itoa(clicks), button)
	default:
		return fmt.Errorf("unsupported input backend %q", backend)
	}
}

func (e *Engine) ComputerScroll(ctx context.Context, in ComputerScrollInput) error {
	backend, err := e.requireComputerControl()
	if err != nil {
		return err
	}
	if in.DX == 0 && in.DY == 0 {
		return nil
	}
	switch backend {
	case "xdg-desktop-portal":
		return e.portalScroll(ctx, in)
	case "wdotool":
		return runInputCommand(ctx, "wdotool", "scroll", strconv.Itoa(in.DX), strconv.Itoa(in.DY))
	case "xdotool":
		return xdotoolScroll(ctx, in.DX, in.DY)
	default:
		return fmt.Errorf("unsupported input backend %q", backend)
	}
}

func xdotoolScroll(ctx context.Context, dx, dy int) error {
	steps := func(value int, negativeButton, positiveButton string) error {
		if value == 0 {
			return nil
		}
		button := positiveButton
		if value < 0 {
			value = -value
			button = negativeButton
		}
		if value > 50 {
			return errors.New("scroll magnitude must be <= 50")
		}
		return runInputCommand(ctx, "xdotool", "click", "--repeat", strconv.Itoa(value), button)
	}
	if err := steps(dy, "4", "5"); err != nil {
		return err
	}
	return steps(dx, "6", "7")
}

func (e *Engine) ComputerType(ctx context.Context, in ComputerTypeInput) error {
	backend, err := e.requireComputerControl()
	if err != nil {
		return err
	}
	if in.Text == "" {
		return nil
	}
	delay := in.DelayMS
	if delay < 0 || delay > 1000 {
		return errors.New("delay_ms must be between 0 and 1000")
	}
	if backend == "xdg-desktop-portal" {
		return e.portalType(ctx, in)
	}

	args := []string{"type", "--clearmodifiers"}
	if delay > 0 {
		args = append(args, "--delay", strconv.Itoa(delay))
	}
	args = append(args, in.Text)
	return runInputCommand(ctx, backend, args...)
}

func (e *Engine) ComputerKey(ctx context.Context, in ComputerKeyInput) error {
	backend, err := e.requireComputerControl()
	if err != nil {
		return err
	}
	keys := strings.TrimSpace(in.Keys)
	if keys == "" {
		return errors.New("keys must not be empty")
	}
	if backend == "xdg-desktop-portal" {
		return e.portalKey(ctx, in)
	}
	return runInputCommand(ctx, backend, "key", "--clearmodifiers", keys)
}
