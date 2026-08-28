package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

const (
	portalService   = "org.freedesktop.portal.Desktop"
	portalPath      = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	remoteDesktopIF = "org.freedesktop.portal.RemoteDesktop"
	screenCastIF    = "org.freedesktop.portal.ScreenCast"
	requestIF       = "org.freedesktop.portal.Request"
	sessionIF       = "org.freedesktop.portal.Session"
)

type portalStream struct {
	NodeID     uint32
	Properties map[string]dbus.Variant
}

type portalRemoteDesktopSession struct {
	conn          *dbus.Conn
	ownsConn      bool
	session       dbus.ObjectPath
	streamID      uint32
	streamWidth   int
	streamHeight  int
	restoreToken  string
	signals       chan *dbus.Signal
	closedSignals chan *dbus.Signal
	closed        chan struct{}
	closedOnce    sync.Once
	notifyMu      sync.Mutex
}

func connectDesktopSessionBus() (*dbus.Conn, error) {
	if address := strings.TrimSpace(desktopEnvValue("DBUS_SESSION_BUS_ADDRESS")); address != "" {
		if conn, err := dbus.Connect(address); err == nil {
			return conn, nil
		}
	}
	return dbus.ConnectSessionBus()
}

func portalRemoteDesktopAvailableOn(conn *dbus.Conn) bool {
	if conn == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var version dbus.Variant
	call := conn.Object(portalService, portalPath).CallWithContext(
		ctx, "org.freedesktop.DBus.Properties.Get", 0, remoteDesktopIF, "version")
	if call.Err != nil || call.Store(&version) != nil {
		return false
	}
	value, ok := variantInt(version)
	return ok && value >= 1
}

func portalRemoteDesktopAvailable() bool {
	conn, err := connectDesktopSessionBus()
	if err != nil {
		return false
	}
	defer conn.Close()
	return portalRemoteDesktopAvailableOn(conn)
}

func portalToken(prefix string) string {
	return prefix + "_" + protocol.NewID()
}

func portalOptions(values map[string]any) map[string]dbus.Variant {
	out := make(map[string]dbus.Variant, len(values))
	for key, value := range values {
		out[key] = dbus.MakeVariant(value)
	}
	return out
}

func normalizeComputerPersistMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "process":
		return "process", nil
	case "none", "persistent":
		return strings.ToLower(strings.TrimSpace(mode)), nil
	default:
		return "", fmt.Errorf("computer persist mode must be none, process, or persistent, got %q", mode)
	}
}

func portalPersistMode(mode string) uint32 {
	switch mode {
	case "persistent":
		return 2
	case "process":
		return 1
	default:
		return 0
	}
}
func (p *portalRemoteDesktopSession) close() {
	if p == nil {
		return
	}
	p.closedOnce.Do(func() {
		if p.closed != nil {
			close(p.closed)
		}
	})
	if p.conn != nil && p.session.IsValid() {
		_ = p.conn.Object(portalService, p.session).Call(sessionIF+".Close", dbus.FlagNoReplyExpected).Err
	}
	if p.conn != nil {
		_ = p.conn.RemoveMatchSignal(
			dbus.WithMatchInterface(requestIF), dbus.WithMatchMember("Response"))
		if p.session.IsValid() {
			_ = p.conn.RemoveMatchSignal(
				dbus.WithMatchObjectPath(p.session), dbus.WithMatchInterface(sessionIF), dbus.WithMatchMember("Closed"))
		}
		if p.signals != nil {
			p.conn.RemoveSignal(p.signals)
		}
		if p.closedSignals != nil {
			p.conn.RemoveSignal(p.closedSignals)
		}
		if p.ownsConn {
			_ = p.conn.Close()
		}
	}
}

func (p *portalRemoteDesktopSession) isClosed() bool {
	if p == nil || p.closed == nil {
		return true
	}
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

func (p *portalRemoteDesktopSession) watchClosed() {
	for {
		select {
		case <-p.closed:
			return
		case signal, ok := <-p.closedSignals:
			if !ok {
				return
			}
			if signal == nil || signal.Path != p.session || signal.Name != sessionIF+".Closed" {
				continue
			}
			p.closedOnce.Do(func() { close(p.closed) })
			return
		}
	}
}

func (p *portalRemoteDesktopSession) waitResponse(ctx context.Context, request dbus.ObjectPath) (map[string]dbus.Variant, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case signal, ok := <-p.signals:
			if !ok {
				return nil, errors.New("desktop portal signal channel closed")
			}
			if signal == nil || signal.Path != request || signal.Name != requestIF+".Response" {
				continue
			}
			if len(signal.Body) != 2 {
				return nil, errors.New("malformed desktop portal response")
			}
			code, ok := signal.Body[0].(uint32)
			if !ok {
				return nil, errors.New("malformed desktop portal response code")
			}
			results, ok := signal.Body[1].(map[string]dbus.Variant)
			if !ok {
				return nil, errors.New("malformed desktop portal response results")
			}
			switch code {
			case 0:
				return results, nil
			case 1:
				return nil, errors.New("desktop portal request cancelled by user")
			case 2:
				return nil, errors.New("desktop portal request denied")
			default:
				return nil, fmt.Errorf("desktop portal request failed with code %d", code)
			}
		}
	}
}
func (p *portalRemoteDesktopSession) request(ctx context.Context, method string, args ...any) (map[string]dbus.Variant, error) {
	var request dbus.ObjectPath
	call := p.conn.Object(portalService, portalPath).CallWithContext(ctx, method, 0, args...)
	if call.Err != nil {
		return nil, call.Err
	}
	if err := call.Store(&request); err != nil {
		return nil, err
	}
	if !request.IsValid() {
		return nil, errors.New("desktop portal returned invalid request path")
	}
	return p.waitResponse(ctx, request)
}

func portalObjectPath(value dbus.Variant) (dbus.ObjectPath, bool) {
	switch v := value.Value().(type) {
	case dbus.ObjectPath:
		return v, v.IsValid()
	case string:
		path := dbus.ObjectPath(v)
		return path, path.IsValid()
	default:
		return "", false
	}
}

func portalPair(value dbus.Variant) (int, int, bool) {
	var signed struct{ A, B int32 }
	if value.Store(&signed) == nil {
		return int(signed.A), int(signed.B), true
	}
	var unsigned struct{ A, B uint32 }
	if value.Store(&unsigned) == nil {
		return int(unsigned.A), int(unsigned.B), true
	}
	switch v := value.Value().(type) {
	case []int32:
		if len(v) >= 2 {
			return int(v[0]), int(v[1]), true
		}
	case []uint32:
		if len(v) >= 2 {
			return int(v[0]), int(v[1]), true
		}
	}
	return 0, 0, false
}
func newPortalRemoteDesktopSession(ctx context.Context, conn *dbus.Conn, persistMode uint32, restoreToken string) (*portalRemoteDesktopSession, error) {
	ownsConn := false
	if conn == nil {
		var err error
		conn, err = connectDesktopSessionBus()
		if err != nil {
			return nil, err
		}
		ownsConn = true
	}
	p := &portalRemoteDesktopSession{conn: conn, ownsConn: ownsConn, signals: make(chan *dbus.Signal, 32), closedSignals: make(chan *dbus.Signal, 8), closed: make(chan struct{})}
	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface(requestIF), dbus.WithMatchMember("Response")); err != nil {
		conn.Close()
		return nil, err
	}
	conn.Signal(p.signals)
	fail := func(err error) (*portalRemoteDesktopSession, error) { p.close(); return nil, err }

	createCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	results, err := p.request(createCtx, remoteDesktopIF+".CreateSession", portalOptions(map[string]any{
		"handle_token": portalToken("create"), "session_handle_token": portalToken("session"),
	}))
	cancel()
	if err != nil {
		return fail(fmt.Errorf("create remote desktop session: %w", err))
	}
	session, ok := portalObjectPath(results["session_handle"])
	if !ok {
		return fail(errors.New("desktop portal did not return a session handle"))
	}
	p.session = session
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(p.session), dbus.WithMatchInterface(sessionIF), dbus.WithMatchMember("Closed")); err != nil {
		return fail(fmt.Errorf("watch remote desktop session: %w", err))
	}
	conn.Signal(p.closedSignals)
	go p.watchClosed()

	deviceOptions := map[string]any{
		"handle_token": portalToken("devices"), "types": uint32(3),
	}
	if persistMode > 0 {
		deviceOptions["persist_mode"] = persistMode
	}
	if strings.TrimSpace(restoreToken) != "" {
		deviceOptions["restore_token"] = restoreToken
	}
	selectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = p.request(selectCtx, remoteDesktopIF+".SelectDevices", p.session, portalOptions(deviceOptions))
	cancel()
	if err != nil {
		return fail(fmt.Errorf("select remote desktop devices: %w", err))
	}

	sourceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err = p.request(sourceCtx, screenCastIF+".SelectSources", p.session, portalOptions(map[string]any{
		"handle_token": portalToken("sources"), "types": uint32(1),
		"multiple": false, "cursor_mode": uint32(1),
	}))
	cancel()
	if err != nil {
		return fail(fmt.Errorf("select remote desktop monitor: %w", err))
	}

	// Start is the point where the compositor may display its permission dialog.
	startCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	results, err = p.request(startCtx, remoteDesktopIF+".Start", p.session, "", portalOptions(map[string]any{
		"handle_token": portalToken("start"),
	}))
	cancel()
	if err != nil {
		return fail(fmt.Errorf("start remote desktop session: %w", err))
	}
	if token, ok := results["restore_token"]; ok {
		if value, ok := token.Value().(string); ok {
			p.restoreToken = strings.TrimSpace(value)
		}
	}
	if streams, ok := results["streams"]; ok {
		var decoded []portalStream
		if streams.Store(&decoded) == nil && len(decoded) > 0 {
			p.streamID = decoded[0].NodeID
			for _, key := range []string{"logical_size", "size"} {
				if size, exists := decoded[0].Properties[key]; exists {
					if w, h, ok := portalPair(size); ok {
						p.streamWidth, p.streamHeight = w, h
						break
					}
				}
			}
		}
	}
	if p.streamID == 0 {
		return fail(errors.New("desktop portal returned no screen-cast stream"))
	}
	return p, nil
}
func (e *Engine) portalTokenPath() string {
	return filepath.Join(e.cfg.StateDir, "computer", "portal-restore-token")
}

func (e *Engine) loadPortalRestoreTokenLocked() {
	if e.portalTokenLoaded {
		return
	}
	e.portalTokenLoaded = true
	if e.cfg.ComputerPersistMode != "persistent" {
		return
	}
	data, err := os.ReadFile(e.portalTokenPath())
	if err == nil {
		e.portalRestoreToken = strings.TrimSpace(string(data))
	}
}

func (e *Engine) clearPortalRestoreTokenLocked() {
	e.portalRestoreToken = ""
	if e.cfg.ComputerPersistMode == "persistent" {
		_ = os.Remove(e.portalTokenPath())
	}
}

func (e *Engine) savePortalRestoreTokenLocked(token string) error {
	e.portalRestoreToken = strings.TrimSpace(token)
	if e.cfg.ComputerPersistMode != "persistent" || e.portalRestoreToken == "" {
		return nil
	}
	dir := filepath.Dir(e.portalTokenPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp := e.portalTokenPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(e.portalRestoreToken+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, e.portalTokenPath())
}

func (e *Engine) ensurePortalConnLocked() error {
	if e.portalConn != nil && portalRemoteDesktopAvailableOn(e.portalConn) {
		return nil
	}
	if e.portalConn != nil {
		_ = e.portalConn.Close()
		e.portalConn = nil
	}
	conn, err := connectDesktopSessionBus()
	if err != nil {
		return err
	}
	if !portalRemoteDesktopAvailableOn(conn) {
		_ = conn.Close()
		return errors.New("XDG RemoteDesktop portal is unavailable")
	}
	e.portalConn = conn
	return nil
}

func (e *Engine) portalSession(ctx context.Context) (*portalRemoteDesktopSession, error) {
	e.portalMu.Lock()
	defer e.portalMu.Unlock()
	if e.portal != nil && !e.portal.isClosed() {
		return e.portal, nil
	}
	if e.portal != nil {
		e.portal.close()
		e.portal = nil
	}
	if err := e.ensurePortalConnLocked(); err != nil {
		return nil, err
	}

	e.loadPortalRestoreTokenLocked()
	restoreToken := e.portalRestoreToken
	if restoreToken != "" {
		// Restore tokens are single-use. A successful Start will provide a replacement.
		e.clearPortalRestoreTokenLocked()
	}
	portal, err := newPortalRemoteDesktopSession(ctx, e.portalConn, portalPersistMode(e.cfg.ComputerPersistMode), restoreToken)
	if err != nil {
		return nil, err
	}
	if err := e.savePortalRestoreTokenLocked(portal.restoreToken); err != nil {
		portal.close()
		return nil, fmt.Errorf("save desktop portal restore token: %w", err)
	}
	e.portal = portal
	return portal, nil
}

func (p *portalRemoteDesktopSession) notify(ctx context.Context, method string, args ...any) error {
	p.notifyMu.Lock()
	defer p.notifyMu.Unlock()
	if p.isClosed() {
		return errors.New("desktop portal session is closed")
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	call := p.conn.Object(portalService, portalPath).CallWithContext(callCtx, remoteDesktopIF+"."+method, 0, args...)
	if call.Err != nil {
		p.closedOnce.Do(func() { close(p.closed) })
	}
	return call.Err
}

func emptyPortalOptions() map[string]dbus.Variant { return map[string]dbus.Variant{} }
func scalePortalPoint(x, y, shotW, shotH, streamW, streamH int) (float64, float64) {
	px, py := float64(x), float64(y)
	if streamW > 0 && streamH > 0 && shotW > 0 && shotH > 0 {
		px = px * float64(streamW) / float64(shotW)
		py = py * float64(streamH) / float64(shotH)
	}
	if px < 0 {
		px = 0
	}
	if py < 0 {
		py = 0
	}
	if streamW > 0 && px > float64(streamW-1) {
		px = float64(streamW - 1)
	}
	if streamH > 0 && py > float64(streamH-1) {
		py = float64(streamH - 1)
	}
	return px, py
}

func (e *Engine) portalMove(ctx context.Context, in ComputerMoveInput) error {
	p, err := e.portalSession(ctx)
	if err != nil {
		return err
	}
	e.computerMu.Lock()
	shotW, shotH := e.lastScreenshotWidth, e.lastScreenshotHeight
	e.computerMu.Unlock()
	x, y := scalePortalPoint(in.X, in.Y, shotW, shotH, p.streamWidth, p.streamHeight)
	return p.notify(ctx, "NotifyPointerMotionAbsolute", p.session, emptyPortalOptions(), p.streamID, x, y)
}

func portalButtonCode(button string) (int32, error) {
	switch strings.ToLower(strings.TrimSpace(button)) {
	case "", "left", "1":
		return 0x110, nil
	case "right", "3":
		return 0x111, nil
	case "middle", "2":
		return 0x112, nil
	case "back", "8":
		return 0x113, nil
	case "forward", "9":
		return 0x114, nil
	default:
		return 0, fmt.Errorf("unsupported mouse button %q", button)
	}
}
func (e *Engine) portalClick(ctx context.Context, in ComputerClickInput) error {
	p, err := e.portalSession(ctx)
	if err != nil {
		return err
	}
	button, err := portalButtonCode(in.Button)
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
	for i := 0; i < clicks; i++ {
		if err := p.notify(ctx, "NotifyPointerButton", p.session, emptyPortalOptions(), button, uint32(1)); err != nil {
			return err
		}
		if err := p.notify(ctx, "NotifyPointerButton", p.session, emptyPortalOptions(), button, uint32(0)); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) portalScroll(ctx context.Context, in ComputerScrollInput) error {
	p, err := e.portalSession(ctx)
	if err != nil {
		return err
	}
	if in.DY != 0 {
		if in.DY < -50 || in.DY > 50 {
			return errors.New("vertical scroll magnitude must be <= 50")
		}
		if err := p.notify(ctx, "NotifyPointerAxisDiscrete", p.session, emptyPortalOptions(), uint32(0), int32(in.DY)); err != nil {
			return err
		}
	}
	if in.DX != 0 {
		if in.DX < -50 || in.DX > 50 {
			return errors.New("horizontal scroll magnitude must be <= 50")
		}
		if err := p.notify(ctx, "NotifyPointerAxisDiscrete", p.session, emptyPortalOptions(), uint32(1), int32(in.DX)); err != nil {
			return err
		}
	}
	return nil
}
func runeKeysym(r rune) uint32 {
	if r >= 0x20 && r <= 0xff {
		return uint32(r)
	}
	if r > 0xff && r <= 0x10ffff {
		return 0x01000000 | uint32(r)
	}
	switch r {
	case '\n', '\r':
		return 0xff0d
	case '\t':
		return 0xff09
	case '\b':
		return 0xff08
	default:
		return uint32(r)
	}
}

func namedKeysym(name string) (uint32, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	aliases := map[string]uint32{
		"backspace": 0xff08, "tab": 0xff09, "return": 0xff0d, "enter": 0xff0d,
		"escape": 0xff1b, "esc": 0xff1b, "home": 0xff50, "left": 0xff51,
		"up": 0xff52, "right": 0xff53, "down": 0xff54, "pageup": 0xff55,
		"pagedown": 0xff56, "end": 0xff57, "insert": 0xff63, "delete": 0xffff,
		"shift": 0xffe1, "shift_l": 0xffe1, "ctrl": 0xffe3, "control": 0xffe3,
		"control_l": 0xffe3, "alt": 0xffe9, "alt_l": 0xffe9, "super": 0xffeb,
		"meta": 0xffeb, "win": 0xffeb, "super_l": 0xffeb, "space": 0x20,
	}
	if value, ok := aliases[n]; ok {
		return value, true
	}
	if len(n) >= 2 && n[0] == 'f' {
		var number int
		if _, err := fmt.Sscanf(n, "f%d", &number); err == nil && number >= 1 && number <= 35 {
			return uint32(0xffbd + number), true
		}
	}
	runes := []rune(name)
	if len(runes) == 1 {
		return runeKeysym(runes[0]), true
	}
	return 0, false
}
func (p *portalRemoteDesktopSession) keysym(ctx context.Context, sym uint32, pressed bool) error {
	state := uint32(0)
	if pressed {
		state = 1
	}
	return p.notify(ctx, "NotifyKeyboardKeysym", p.session, emptyPortalOptions(), int32(sym), state)
}

func (e *Engine) portalType(ctx context.Context, in ComputerTypeInput) error {
	p, err := e.portalSession(ctx)
	if err != nil {
		return err
	}
	delay := in.DelayMS
	if delay < 0 || delay > 1000 {
		return errors.New("delay_ms must be between 0 and 1000")
	}
	for _, r := range in.Text {
		sym := runeKeysym(r)
		if err := p.keysym(ctx, sym, true); err != nil {
			return err
		}
		if err := p.keysym(ctx, sym, false); err != nil {
			return err
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(delay) * time.Millisecond):
			}
		}
	}
	return nil
}

func (e *Engine) portalKey(ctx context.Context, in ComputerKeyInput) error {
	p, err := e.portalSession(ctx)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimSpace(in.Keys), "+")
	if len(parts) == 0 {
		return errors.New("keys must not be empty")
	}
	syms := make([]uint32, 0, len(parts))
	for _, part := range parts {
		sym, ok := namedKeysym(part)
		if !ok {
			return fmt.Errorf("unsupported key %q for portal backend", part)
		}
		syms = append(syms, sym)
	}
	for _, sym := range syms {
		if err := p.keysym(ctx, sym, true); err != nil {
			return err
		}
	}
	for i := len(syms) - 1; i >= 0; i-- {
		if err := p.keysym(ctx, syms[i], false); err != nil {
			return err
		}
	}
	return nil
}
