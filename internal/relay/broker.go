package relay

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

type Broker struct {
	mu             sync.RWMutex
	peers          map[string]*peer
	callSlots      chan struct{}
	maxConnections int
	authMu         sync.RWMutex
	authorizer     func(device, credentialHash string) bool
}

const maxRPCTime = 2 * time.Minute

type peer struct {
	device         string
	conn           *websocket.Conn
	writeMu        sync.Mutex
	pendingMu      sync.Mutex
	pending        map[string]chan protocol.Response
	done           chan struct{}
	doneOnce       sync.Once
	stateMu        sync.RWMutex
	connectedAt    time.Time
	lastSeen       time.Time
	capabilities   protocol.AgentCapabilities
	credentialHash string
}

type RemoteCaller struct {
	Broker *Broker
	Device string
}

func NewBroker() *Broker {
	return &Broker{peers: make(map[string]*peer), callSlots: make(chan struct{}, 32), maxConnections: 64}
}

// SetAgentConnectionAuthorizer installs a callback used before accepting an
// Agent connection and before every brokered RPC. The callback receives only a
// SHA-256 fingerprint of the bearer token, never the raw token. Rechecking at
// call time makes OAuth revoke, device disable, and the Relay kill switch take
// effect for already-established WebSockets as well as new connections.
func (b *Broker) SetAgentConnectionAuthorizer(authorizer func(device, credentialHash string) bool) {
	b.authMu.Lock()
	b.authorizer = authorizer
	b.authMu.Unlock()
}

func (b *Broker) peerAuthorized(p *peer) bool {
	b.authMu.RLock()
	authorizer := b.authorizer
	b.authMu.RUnlock()
	return authorizer == nil || authorizer(p.device, p.credentialHash)
}

func (c RemoteCaller) Call(ctx context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
	return c.Broker.Call(ctx, c.Device, method, raw)
}

func (b *Broker) Call(ctx context.Context, device, method string, raw json.RawMessage) (json.RawMessage, error) {
	rpcCtx, cancel := context.WithTimeout(ctx, maxRPCTime)
	defer cancel()
	b.mu.RLock()
	p := b.peers[device]
	b.mu.RUnlock()
	if p == nil {
		return nil, fmt.Errorf("device %q is offline", device)
	}
	if !b.peerAuthorized(p) {
		p.close("authorization revoked")
		return nil, errors.New("agent authorization revoked")
	}
	select {
	case b.callSlots <- struct{}{}:
		defer func() { <-b.callSlots }()
	case <-rpcCtx.Done():
		return nil, rpcCtx.Err()
	}

	id := protocol.NewID()
	ch := make(chan protocol.Response, 1)
	p.pendingMu.Lock()
	p.pending[id] = ch
	p.pendingMu.Unlock()
	defer func() {
		p.pendingMu.Lock()
		delete(p.pending, id)
		p.pendingMu.Unlock()
	}()

	request := protocol.Request{ID: id, Method: method, Args: raw}
	if err := p.writeJSON(rpcCtx, request); err != nil {
		return nil, err
	}
	select {
	case response := <-ch:
		if response.Error != "" {
			return nil, errors.New(response.Error)
		}
		return response.Result, nil
	case <-p.done:
		return nil, errors.New("device disconnected")
	case <-rpcCtx.Done():
		return nil, rpcCtx.Err()
	}
}

func (p *peer) writeJSON(ctx context.Context, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.conn.Write(ctx, websocket.MessageText, data)
}

func (p *peer) readLoop(onClose func()) {
	defer func() {
		p.doneOnce.Do(func() { close(p.done) })
		onClose()
	}()
	for {
		_, data, err := p.conn.Read(context.Background())
		if err != nil {
			return
		}
		p.stateMu.Lock()
		p.lastSeen = time.Now()
		p.stateMu.Unlock()
		var request protocol.Request
		if len(data) <= 64<<10 && json.Unmarshal(data, &request) == nil && request.ID != "" && request.Method == "agent_hello" {
			var capabilities protocol.AgentCapabilities
			if json.Unmarshal(request.Args, &capabilities) == nil {
				p.stateMu.Lock()
				p.capabilities = capabilities
				p.stateMu.Unlock()
			}
			continue
		}
		var response protocol.Response
		if json.Unmarshal(data, &response) != nil || response.ID == "" {
			continue
		}
		p.pendingMu.Lock()
		ch := p.pending[response.ID]
		p.pendingMu.Unlock()
		if ch != nil {
			select {
			case ch <- response:
			default:
			}
		}
	}
}

func (p *peer) close(_ string) {
	p.doneOnce.Do(func() { close(p.done) })
	// A revoked/replaced peer must not make the HTTP/RPC path wait for a
	// close-handshake from an unresponsive client.
	_ = p.conn.CloseNow()
}

func (b *Broker) AgentHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		device := deviceRoute(r)
		if device == "" {
			http.Error(w, "invalid device", http.StatusBadRequest)
			return
		}
		b.acceptAgent(w, r, device)
	}
}

func deviceRoute(r *http.Request) string {
	if device := strings.TrimSpace(r.PathValue("device")); protocol.ValidDeviceName(device) {
		return device
	}
	if id := strings.TrimSpace(r.PathValue("id")); protocol.ValidDeviceID(id) {
		return "id/" + id
	}
	return ""
}

func (b *Broker) LegacyAgentHandler(agentToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validBearer(r, agentToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		device := strings.TrimSpace(r.URL.Query().Get("device"))
		if !protocol.ValidDeviceName(device) {
			http.Error(w, "invalid device", http.StatusBadRequest)
			return
		}
		b.acceptAgent(w, r, device)
	}
}

func (b *Broker) acceptAgent(w http.ResponseWriter, r *http.Request, device string) {
	b.mu.RLock()
	_, replacing := b.peers[device]
	full := len(b.peers) >= b.maxConnections
	b.mu.RUnlock()
	if full && !replacing {
		http.Error(w, "agent connection limit reached", http.StatusServiceUnavailable)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}
	conn.SetReadLimit(32 << 20)
	now := time.Now()
	p := &peer{device: device, conn: conn, credentialHash: TokenFingerprint(bearerToken(r.Header.Get("Authorization"))), pending: make(map[string]chan protocol.Response), done: make(chan struct{}), connectedAt: now, lastSeen: now}
	if !b.peerAuthorized(p) {
		_ = conn.Close(websocket.StatusPolicyViolation, "authorization revoked")
		return
	}

	b.mu.Lock()
	old := b.peers[device]
	b.peers[device] = p
	b.mu.Unlock()
	if old != nil {
		old.close("replaced by a new connection")
	}
	go p.readLoop(func() {
		b.mu.Lock()
		if b.peers[device] == p {
			delete(b.peers, device)
		}
		b.mu.Unlock()
	})
}

func validBearer(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	provided := bearerToken(r.Header.Get("Authorization"))
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// TokenFingerprint is used for in-memory connection authorization checks. It
// is intentionally one-way so peer status and broker state never retain a raw
// OAuth bearer value.
func TokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (b *Broker) Devices() []string {
	b.mu.RLock()
	devices := make([]string, 0, len(b.peers))
	for device := range b.peers {
		devices = append(devices, device)
	}
	b.mu.RUnlock()
	sort.Strings(devices)
	return devices
}

type DeviceStatus struct {
	Device       string
	Online       bool
	ConnectedAt  time.Time
	LastSeen     time.Time
	InFlight     int
	Capabilities protocol.AgentCapabilities
}

func (b *Broker) DeviceStatuses() map[string]DeviceStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	statuses := make(map[string]DeviceStatus, len(b.peers))
	for name, peer := range b.peers {
		peer.stateMu.RLock()
		peer.pendingMu.Lock()
		statuses[name] = DeviceStatus{Device: name, Online: true, ConnectedAt: peer.connectedAt, LastSeen: peer.lastSeen, InFlight: len(peer.pending), Capabilities: peer.capabilities}
		peer.pendingMu.Unlock()
		peer.stateMu.RUnlock()
	}
	return statuses
}
