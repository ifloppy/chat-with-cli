package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

const (
	atspiBusService   = "org.a11y.Bus"
	atspiBusPath      = dbus.ObjectPath("/org/a11y/bus")
	atspiRegistry     = "org.a11y.atspi.Registry"
	atspiRootPath     = dbus.ObjectPath("/org/a11y/atspi/accessible/root")
	atspiAccessible   = "org.a11y.atspi.Accessible"
	atspiComponent    = "org.a11y.atspi.Component"
	atspiAction       = "org.a11y.atspi.Action"
	atspiEditableText = "org.a11y.atspi.EditableText"
)

type atspiRef struct {
	Bus  string
	Path dbus.ObjectPath
}

func atspiReadCall(ctx context.Context, obj dbus.BusObject, method string, args ...any) *dbus.Call {
	callCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	return obj.CallWithContext(callCtx, method, 0, args...)
}

type atspiActionInfo struct {
	Name        string
	Description string
	KeyBinding  string
}

type atspiWalker struct {
	conn           *dbus.Conn
	maxDepth       int
	maxNodes       int
	query          string
	role           string
	requiredStates map[string]bool
	maxResults     int
	all            []ComputerUINode
	matches        []ComputerUINode
	visited        int
	truncated      bool
}

func encodeUIRef(ref atspiRef) string {
	raw := ref.Bus + "\x00" + string(ref.Path)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeUIRef(value string) (atspiRef, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return atspiRef{}, errors.New("invalid UI ref")
	}
	parts := strings.SplitN(string(data), "\x00", 2)
	if len(parts) != 2 || parts[0] == "" || !dbus.ObjectPath(parts[1]).IsValid() {
		return atspiRef{}, errors.New("invalid UI ref")
	}
	return atspiRef{Bus: parts[0], Path: dbus.ObjectPath(parts[1])}, nil
}

func connectATSPI() (*dbus.Conn, error) {
	session, err := connectDesktopSessionBus()
	if err != nil {
		return nil, fmt.Errorf("connect session bus: %w", err)
	}
	var address string
	call := session.Object(atspiBusService, atspiBusPath).
		Call(atspiBusService+".GetAddress", 0)
	if call.Err != nil {
		session.Close()
		return nil, fmt.Errorf("get AT-SPI bus address: %w", call.Err)
	}
	if err := call.Store(&address); err != nil {
		session.Close()
		return nil, fmt.Errorf("decode AT-SPI bus address: %w", err)
	}
	session.Close()
	conn, err := dbus.Connect(strings.TrimSpace(address))
	if err != nil {
		return nil, fmt.Errorf("connect AT-SPI bus: %w", err)
	}
	return conn, nil
}
func atspiRootChildren(ctx context.Context, conn *dbus.Conn) ([]atspiRef, error) {
	var children []atspiRef
	call := atspiReadCall(ctx, conn.Object(atspiRegistry, atspiRootPath), atspiAccessible+".GetChildren")
	if call.Err != nil {
		return nil, call.Err
	}
	if err := call.Store(&children); err != nil {
		return nil, err
	}
	return children, nil
}

func atspiProperty(ctx context.Context, conn *dbus.Conn, ref atspiRef, property string) (dbus.Variant, error) {
	var value dbus.Variant
	call := atspiReadCall(ctx, conn.Object(ref.Bus, ref.Path),
		"org.freedesktop.DBus.Properties.Get", atspiAccessible, property)
	if call.Err != nil {
		return value, call.Err
	}
	if err := call.Store(&value); err != nil {
		return value, err
	}
	return value, nil
}

func atspiStringProperty(ctx context.Context, conn *dbus.Conn, ref atspiRef, property string) string {
	value, err := atspiProperty(ctx, conn, ref, property)
	if err != nil {
		return ""
	}
	text, _ := value.Value().(string)
	return text
}
func atspiRoleName(ctx context.Context, conn *dbus.Conn, ref atspiRef) string {
	var role string
	call := atspiReadCall(ctx, conn.Object(ref.Bus, ref.Path), atspiAccessible+".GetRoleName")
	if call.Err == nil {
		_ = call.Store(&role)
	}
	return role
}

func atspiChildren(ctx context.Context, conn *dbus.Conn, ref atspiRef) []atspiRef {
	var children []atspiRef
	call := atspiReadCall(ctx, conn.Object(ref.Bus, ref.Path), atspiAccessible+".GetChildren")
	if call.Err == nil {
		_ = call.Store(&children)
	}
	return children
}

func atspiInterfaces(ctx context.Context, conn *dbus.Conn, ref atspiRef) map[string]bool {
	var values []string
	call := atspiReadCall(ctx, conn.Object(ref.Bus, ref.Path), atspiAccessible+".GetInterfaces")
	if call.Err != nil || call.Store(&values) != nil {
		return nil
	}
	out := make(map[string]bool, len(values))
	for _, value := range values {
		name := strings.ToLower(strings.TrimSpace(value))
		name = strings.TrimPrefix(name, "org.a11y.atspi.")
		out[name] = true
	}
	return out
}
func atspiBounds(ctx context.Context, conn *dbus.Conn, ref atspiRef, ifaces map[string]bool) ComputerUIBounds {
	if len(ifaces) > 0 && !ifaces["component"] {
		return ComputerUIBounds{}
	}
	var rect struct{ X, Y, Width, Height int32 }
	call := atspiReadCall(ctx, conn.Object(ref.Bus, ref.Path), atspiComponent+".GetExtents", uint32(0))
	if call.Err != nil || call.Store(&rect) != nil {
		return ComputerUIBounds{}
	}
	return ComputerUIBounds{X: int(rect.X), Y: int(rect.Y), Width: int(rect.Width), Height: int(rect.Height)}
}

func atspiActions(ctx context.Context, conn *dbus.Conn, ref atspiRef, ifaces map[string]bool) []ComputerUIAction {
	if len(ifaces) > 0 && !ifaces["action"] {
		return nil
	}
	var values []atspiActionInfo
	call := atspiReadCall(ctx, conn.Object(ref.Bus, ref.Path), atspiAction+".GetActions")
	if call.Err != nil || call.Store(&values) != nil {
		return nil
	}
	out := make([]ComputerUIAction, 0, len(values))
	for i, value := range values {
		out = append(out, ComputerUIAction{
			Index: i, Name: value.Name, Description: value.Description, KeyBinding: value.KeyBinding,
		})
	}
	return out
}

func normalizeUIBounds(depth, nodes, results int) (int, int, int) {
	if depth <= 0 {
		depth = 8
	}
	if depth > 20 {
		depth = 20
	}
	if nodes <= 0 {
		nodes = 400
	}
	if nodes > 2000 {
		nodes = 2000
	}
	if results <= 0 {
		results = 100
	}
	if results > 500 {
		results = 500
	}
	return depth, nodes, results
}
func (w *atspiWalker) walk(ctx context.Context, ref atspiRef, app string, depth int) {
	if ctx.Err() != nil || depth > w.maxDepth || w.visited >= w.maxNodes {
		if w.visited >= w.maxNodes {
			w.truncated = true
		}
		return
	}
	if ref.Bus == "" || !ref.Path.IsValid() || ref.Path == "/org/a11y/atspi/null" {
		return
	}
	w.visited++
	states, managesDescendants := atspiStates(ctx, w.conn, ref)
	children := []atspiRef(nil)
	if !managesDescendants {
		children = atspiChildren(ctx, w.conn, ref)
	}
	ifaces := atspiInterfaces(ctx, w.conn, ref)
	node := ComputerUINode{
		Ref: encodeUIRef(ref), App: app, Depth: depth,
		Name:        atspiStringProperty(ctx, w.conn, ref, "Name"),
		Description: atspiStringProperty(ctx, w.conn, ref, "Description"),
		Role:        atspiRoleName(ctx, w.conn, ref), ChildCount: len(children), States: states,
		Bounds:  atspiBounds(ctx, w.conn, ref, ifaces),
		Actions: atspiActions(ctx, w.conn, ref, ifaces),
	}
	w.all = append(w.all, node)
	if w.matchesNode(node) {
		if len(w.matches) < w.maxResults {
			w.matches = append(w.matches, node)
		} else {
			w.truncated = true
		}
	}
	if w.matchLimitReached() {
		w.truncated = true
		return
	}
	for _, child := range children {
		w.walk(ctx, child, app, depth+1)
		if ctx.Err() != nil || w.visited >= w.maxNodes {
			return
		}
		if w.matchLimitReached() {
			return
		}
	}
}

func (w *atspiWalker) matchLimitReached() bool {
	limitedQuery := w.query != "" || w.role != "" || len(w.requiredStates) > 0 || w.maxResults < w.maxNodes
	return limitedQuery && len(w.matches) >= w.maxResults
}

func (w *atspiWalker) matchesNode(node ComputerUINode) bool {
	if w.role != "" && strings.ToLower(strings.TrimSpace(node.Role)) != w.role {
		return false
	}
	if len(w.requiredStates) > 0 {
		states := make(map[string]bool, len(node.States))
		for _, state := range node.States {
			states[strings.ToLower(state)] = true
		}
		for state := range w.requiredStates {
			if !states[state] {
				return false
			}
		}
	}
	if w.query == "" {
		return true
	}
	haystack := strings.ToLower(node.Name + "\n" + node.Description + "\n" + node.Role)
	return strings.Contains(haystack, w.query)
}

func (e *Engine) requireUIRead() error {
	if !e.cfg.AllowScreen {
		return errors.New("UI inspection is disabled; start with --allow-screen or --allow-computer-use")
	}
	return nil
}

func runUIWalkOnConn(ctx context.Context, conn *dbus.Conn, appName, query, role string, requiredStates []string, maxDepth, maxNodes, maxResults int) (*atspiWalker, error) {
	maxDepth, maxNodes, maxResults = normalizeUIBounds(maxDepth, maxNodes, maxResults)
	roots, err := atspiRootChildren(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("list AT-SPI applications: %w", err)
	}
	required := make(map[string]bool, len(requiredStates))
	for _, state := range requiredStates {
		if value := strings.ToLower(strings.TrimSpace(state)); value != "" {
			required[value] = true
		}
	}
	walker := &atspiWalker{conn: conn, maxDepth: maxDepth, maxNodes: maxNodes,
		query: strings.ToLower(strings.TrimSpace(query)), role: strings.ToLower(strings.TrimSpace(role)), requiredStates: required,
		maxResults: maxResults, all: make([]ComputerUINode, 0, min(maxNodes, 128)),
		matches: make([]ComputerUINode, 0, min(maxResults, 64))}
	appFilter := strings.ToLower(strings.TrimSpace(appName))
	for _, root := range roots {
		if ctx.Err() != nil || walker.visited >= maxNodes {
			break
		}
		app := atspiStringProperty(ctx, conn, root, "Name")
		if appFilter != "" && !strings.Contains(strings.ToLower(app), appFilter) {
			continue
		}
		walker.walk(ctx, root, app, 0)
		if walker.matchLimitReached() {
			break
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		walker.truncated = true
	}
	return walker, nil
}

func (e *Engine) runUIWalk(ctx context.Context, appName, query, role string, requiredStates []string, maxDepth, maxNodes, maxResults int) (*atspiWalker, error) {
	if err := e.requireUIRead(); err != nil {
		return nil, err
	}
	walkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := connectATSPI()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return runUIWalkOnConn(walkCtx, conn, appName, query, role, requiredStates, maxDepth, maxNodes, maxResults)
}

func (e *Engine) ComputerUITree(ctx context.Context, in ComputerUITreeInput) (ComputerUIQueryOutput, error) {
	walker, err := e.runUIWalk(ctx, in.AppName, "", "", nil, in.MaxDepth, in.MaxNodes, in.MaxNodes)
	if err != nil {
		return ComputerUIQueryOutput{}, err
	}
	return ComputerUIQueryOutput{Nodes: walker.all, Visited: walker.visited, Truncated: walker.truncated}, nil
}

func (e *Engine) ComputerUIFind(ctx context.Context, in ComputerUIFindInput) (ComputerUIQueryOutput, error) {
	walker, err := e.runUIWalk(ctx, in.AppName, in.Query, in.Role, in.RequiredStates, in.MaxDepth, in.MaxNodes, in.MaxResults)
	if err != nil {
		return ComputerUIQueryOutput{}, err
	}
	return ComputerUIQueryOutput{Nodes: walker.matches, Visited: walker.visited, Truncated: walker.truncated}, nil
}
func (e *Engine) ComputerUIWait(ctx context.Context, in ComputerUIWaitInput) (ComputerUIQueryOutput, error) {
	timeout := in.TimeoutMS
	if timeout <= 0 {
		timeout = 5000
	}
	if timeout > 30000 {
		timeout = 30000
	}
	poll := in.PollIntervalMS
	if poll <= 0 {
		poll = 250
	}
	if poll < 100 {
		poll = 100
	}
	if poll > 2000 {
		poll = 2000
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	for {
		out, err := e.ComputerUIFind(waitCtx, ComputerUIFindInput{
			AppName: in.AppName, Query: in.Query, Role: in.Role, RequiredStates: in.RequiredStates,
			MaxDepth: in.MaxDepth, MaxNodes: in.MaxNodes, MaxResults: in.MaxResults,
		})
		if err == nil && len(out.Nodes) > 0 {
			return out, nil
		}
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return ComputerUIQueryOutput{}, err
		}
		select {
		case <-waitCtx.Done():
			return ComputerUIQueryOutput{}, fmt.Errorf("UI wait timed out after %dms", timeout)
		case <-time.After(time.Duration(poll) * time.Millisecond):
		}
	}
}

func (e *Engine) requireSemanticControl() error {
	if !e.cfg.AllowComputerControl {
		return errors.New("semantic UI control is disabled; start with --allow-computer-use")
	}
	return nil
}
func (e *Engine) ComputerUIFocus(ctx context.Context, in ComputerUIRefInput) (Ack, error) {
	if err := e.requireSemanticControl(); err != nil {
		return Ack{}, err
	}
	ref, err := decodeUIRef(in.Ref)
	if err != nil {
		return Ack{}, err
	}
	conn, err := connectATSPI()
	if err != nil {
		return Ack{}, err
	}
	defer conn.Close()
	focusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var ok bool
	call := conn.Object(ref.Bus, ref.Path).
		CallWithContext(focusCtx, atspiComponent+".GrabFocus", 0)
	if call.Err != nil {
		return Ack{}, fmt.Errorf("focus UI element: %w", call.Err)
	}
	if err := call.Store(&ok); err != nil {
		return Ack{}, err
	}
	if !ok {
		return Ack{}, errors.New("UI element refused focus")
	}
	return Ack{OK: true}, nil
}

func performUIAction(ctx context.Context, conn *dbus.Conn, ref atspiRef, requestedAction string, requestedIndex int, requireUniqueAction bool) (ComputerUIActionOutput, error) {
	actions := atspiActions(ctx, conn, ref, nil)
	if len(actions) == 0 {
		return ComputerUIActionOutput{}, errors.New("UI element exposes no semantic actions")
	}
	index := requestedIndex
	requested := strings.ToLower(strings.TrimSpace(requestedAction))
	if requested != "" {
		index = -1
		for _, action := range actions {
			if strings.ToLower(strings.TrimSpace(action.Name)) == requested {
				index = action.Index
				break
			}
		}
		if index < 0 {
			return ComputerUIActionOutput{}, fmt.Errorf("semantic action %q not found", requestedAction)
		}
	} else if requireUniqueAction {
		if len(actions) != 1 {
			return ComputerUIActionOutput{}, fmt.Errorf("UI element exposes %d actions; specify action explicitly", len(actions))
		}
		index = actions[0].Index
	}
	if index < 0 || index >= len(actions) {
		return ComputerUIActionOutput{}, fmt.Errorf("action index %d is out of range", index)
	}
	var ok bool
	call := conn.Object(ref.Bus, ref.Path).CallWithContext(ctx, atspiAction+".DoAction", 0, int32(index))
	if call.Err != nil {
		return ComputerUIActionOutput{}, fmt.Errorf("perform UI action: %w", call.Err)
	}
	if err := call.Store(&ok); err != nil {
		return ComputerUIActionOutput{}, err
	}
	if !ok {
		return ComputerUIActionOutput{}, errors.New("UI action returned false")
	}
	return ComputerUIActionOutput{OK: true, Index: index, Action: actions[index].Name}, nil
}

func (e *Engine) ComputerUIAction(ctx context.Context, in ComputerUIActionInput) (ComputerUIActionOutput, error) {
	if err := e.requireSemanticControl(); err != nil {
		return ComputerUIActionOutput{}, err
	}
	ref, err := decodeUIRef(in.Ref)
	if err != nil {
		return ComputerUIActionOutput{}, err
	}
	conn, err := connectATSPI()
	if err != nil {
		return ComputerUIActionOutput{}, err
	}
	defer conn.Close()
	actionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return performUIAction(actionCtx, conn, ref, in.Action, in.Index, false)
}

func defaultInvokeStates(states []string) []string {
	if len(states) > 0 {
		return states
	}
	return []string{"showing", "visible", "enabled"}
}

type uniqueUISelector struct {
	AppName, Query, Role string
	RequiredStates       []string
	MaxDepth, MaxNodes   int
	TimeoutMS, PollMS    int
}

type uniqueUISelection struct {
	Status     string
	Message    string
	Matched    int
	Node       *ComputerUINode
	Candidates []ComputerUINode
}

func normalizeUniqueUISelector(sel uniqueUISelector) (time.Duration, time.Duration, bool, uniqueUISelection) {
	if strings.TrimSpace(sel.Query) == "" && strings.TrimSpace(sel.Role) == "" {
		return 0, 0, false, uniqueUISelection{Status: "invalid_selector", Message: "query or role is required"}
	}
	if sel.TimeoutMS < 0 || sel.TimeoutMS > 30000 {
		return 0, 0, false, uniqueUISelection{Status: "invalid_timeout", Message: "timeout_ms must be between 0 and 30000"}
	}
	poll := sel.PollMS
	if poll <= 0 {
		poll = 250
	}
	if poll < 100 || poll > 2000 {
		return 0, 0, false, uniqueUISelection{Status: "invalid_poll_interval", Message: "poll_interval_ms must be between 100 and 2000"}
	}
	total := 15 * time.Second
	wait := sel.TimeoutMS > 0
	if wait {
		total = time.Duration(sel.TimeoutMS) * time.Millisecond
	}
	return total, time.Duration(poll) * time.Millisecond, wait, uniqueUISelection{}
}

func resolveUniqueUI(ctx context.Context, conn *dbus.Conn, sel uniqueUISelector, poll time.Duration, wait bool) (uniqueUISelection, error) {
	for {
		walker, err := runUIWalkOnConn(ctx, conn, sel.AppName, sel.Query, sel.Role,
			defaultInvokeStates(sel.RequiredStates), sel.MaxDepth, sel.MaxNodes, 2)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return uniqueUISelection{Status: "timeout", Message: "UI selector did not become safely invokable before timeout"}, nil
			}
			return uniqueUISelection{}, err
		}
		matched := len(walker.matches)
		if walker.truncated && matched < 2 {
			return uniqueUISelection{Status: "search_incomplete", Matched: matched,
				Candidates: append([]ComputerUINode(nil), walker.matches...),
				Message:    "UI search was truncated before uniqueness could be proven; narrow the selector or raise bounded search limits"}, nil
		}
		if matched > 1 {
			return uniqueUISelection{Status: "ambiguous", Matched: matched,
				Candidates: append([]ComputerUINode(nil), walker.matches...),
				Message:    "selector matched at least two UI elements; refine app_name, query, role, or required_states"}, nil
		}
		if matched == 1 {
			node := walker.matches[0]
			return uniqueUISelection{Status: "ready", Matched: 1, Node: &node}, nil
		}
		if !wait {
			return uniqueUISelection{Status: "not_found", Message: "no UI element matched the selector"}, nil
		}
		select {
		case <-ctx.Done():
			return uniqueUISelection{Status: "timeout", Message: "UI selector did not become safely invokable before timeout"}, nil
		case <-time.After(poll):
		}
	}
}

func invokeOutputFromSelection(sel uniqueUISelection) ComputerUIInvokeOutput {
	return ComputerUIInvokeOutput{Status: sel.Status, Message: sel.Message, Matched: sel.Matched, Node: sel.Node, Candidates: sel.Candidates}
}

func (e *Engine) ComputerUIInvoke(ctx context.Context, in ComputerUIInvokeInput) (ComputerUIInvokeOutput, error) {
	if err := e.requireSemanticControl(); err != nil {
		return ComputerUIInvokeOutput{}, err
	}
	sel := uniqueUISelector{AppName: in.AppName, Query: in.Query, Role: in.Role, RequiredStates: in.RequiredStates,
		MaxDepth: in.MaxDepth, MaxNodes: in.MaxNodes, TimeoutMS: in.TimeoutMS, PollMS: in.PollIntervalMS}
	total, poll, wait, invalid := normalizeUniqueUISelector(sel)
	if invalid.Status != "" {
		return invokeOutputFromSelection(invalid), nil
	}
	conn, err := connectATSPI()
	if err != nil {
		return ComputerUIInvokeOutput{}, err
	}
	defer conn.Close()
	invokeCtx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	resolved, err := resolveUniqueUI(invokeCtx, conn, sel, poll, wait)
	if err != nil {
		return ComputerUIInvokeOutput{}, err
	}
	if resolved.Status != "ready" || resolved.Node == nil {
		return invokeOutputFromSelection(resolved), nil
	}
	node := *resolved.Node
	ref, err := decodeUIRef(node.Ref)
	if err != nil {
		return ComputerUIInvokeOutput{Status: "stale", Matched: 1, Node: &node, Message: "matched UI ref could not be decoded"}, nil
	}
	performed, err := performUIAction(invokeCtx, conn, ref, in.Action, 0, true)
	if err != nil {
		msg := err.Error()
		status := "failed"
		switch {
		case strings.Contains(msg, "exposes no semantic actions"):
			status = "no_action"
		case strings.Contains(msg, "specify action explicitly"):
			status = "ambiguous_action"
		case strings.Contains(msg, "not found"):
			status = "action_not_found"
		}
		return ComputerUIInvokeOutput{Status: status, Matched: 1, Node: &node, Message: msg}, nil
	}
	return ComputerUIInvokeOutput{Status: "ok", Matched: 1, Node: &node, Index: performed.Index, Action: performed.Action}, nil
}

func setTextOutputFromSelection(sel uniqueUISelection) ComputerUISetTextOutput {
	return ComputerUISetTextOutput{Status: sel.Status, Message: sel.Message, Matched: sel.Matched, Node: sel.Node, Candidates: sel.Candidates}
}

func (e *Engine) ComputerUISetText(ctx context.Context, in ComputerUISetTextInput) (ComputerUISetTextOutput, error) {
	if err := e.requireSemanticControl(); err != nil {
		return ComputerUISetTextOutput{}, err
	}
	if len(in.Text) > 256*1024 || strings.ContainsRune(in.Text, '\x00') {
		return ComputerUISetTextOutput{Status: "invalid_text", Message: "text must be valid D-Bus UTF-8 text without NUL and no larger than 256 KiB"}, nil
	}
	sel := uniqueUISelector{AppName: in.AppName, Query: in.Query, Role: in.Role, RequiredStates: in.RequiredStates,
		MaxDepth: in.MaxDepth, MaxNodes: in.MaxNodes, TimeoutMS: in.TimeoutMS, PollMS: in.PollIntervalMS}
	total, poll, wait, invalid := normalizeUniqueUISelector(sel)
	if invalid.Status != "" {
		return setTextOutputFromSelection(invalid), nil
	}
	conn, err := connectATSPI()
	if err != nil {
		return ComputerUISetTextOutput{}, err
	}
	defer conn.Close()
	setCtx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	resolved, err := resolveUniqueUI(setCtx, conn, sel, poll, wait)
	if err != nil {
		return ComputerUISetTextOutput{}, err
	}
	if resolved.Status != "ready" || resolved.Node == nil {
		return setTextOutputFromSelection(resolved), nil
	}
	node := *resolved.Node
	ref, err := decodeUIRef(node.Ref)
	if err != nil {
		return ComputerUISetTextOutput{Status: "stale", Matched: 1, Node: &node, Message: "matched UI ref could not be decoded"}, nil
	}
	ifaces := atspiInterfaces(setCtx, conn, ref)
	if !ifaces["editabletext"] {
		return ComputerUISetTextOutput{Status: "not_editable", Matched: 1, Node: &node, Message: "matched UI element does not expose AT-SPI EditableText"}, nil
	}
	var ok bool
	call := conn.Object(ref.Bus, ref.Path).CallWithContext(setCtx, atspiEditableText+".SetTextContents", 0, in.Text)
	if call.Err != nil {
		return ComputerUISetTextOutput{Status: "failed", Matched: 1, Node: &node, Message: call.Err.Error()}, nil
	}
	if err := call.Store(&ok); err != nil {
		return ComputerUISetTextOutput{}, err
	}
	if !ok {
		return ComputerUISetTextOutput{Status: "failed", Matched: 1, Node: &node, Message: "EditableText.SetTextContents returned false"}, nil
	}
	return ComputerUISetTextOutput{Status: "ok", Matched: 1, Node: &node, Characters: utf8.RuneCountInString(in.Text)}, nil
}

func atspiAvailable() bool {
	conn, err := connectATSPI()
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func atspiStates(ctx context.Context, conn *dbus.Conn, ref atspiRef) ([]string, bool) {
	var words []uint32
	call := atspiReadCall(ctx, conn.Object(ref.Bus, ref.Path), atspiAccessible+".GetState")
	if call.Err != nil || call.Store(&words) != nil {
		return nil, false
	}
	names := make([]string, 0, 12)
	managesDescendants := false
	for wordIndex, word := range words {
		for bit := 0; bit < 32; bit++ {
			if word&(uint32(1)<<bit) == 0 {
				continue
			}
			state := uint32(wordIndex*32 + bit)
			if name := atspiStateName(state); name != "" {
				names = append(names, name)
			}
			if state == 31 {
				managesDescendants = true
			}
		}
	}
	return names, managesDescendants
}

func atspiStateName(value uint32) string {
	switch value {
	case 1:
		return "active"
	case 3:
		return "busy"
	case 4:
		return "checked"
	case 5:
		return "collapsed"
	case 7:
		return "editable"
	case 8:
		return "enabled"
	case 9:
		return "expandable"
	case 10:
		return "expanded"
	case 11:
		return "focusable"
	case 12:
		return "focused"
	case 15:
		return "iconified"
	case 16:
		return "modal"
	case 20:
		return "pressed"
	case 22:
		return "selectable"
	case 23:
		return "selected"
	case 24:
		return "sensitive"
	case 25:
		return "showing"
	case 30:
		return "visible"
	case 31:
		return "manages_descendants"
	case 32:
		return "indeterminate"
	case 33:
		return "required"
	case 36:
		return "invalid_entry"
	case 39:
		return "default"
	case 41:
		return "checkable"
	case 42:
		return "has_popup"
	case 43:
		return "read_only"
	default:
		return ""
	}
}
