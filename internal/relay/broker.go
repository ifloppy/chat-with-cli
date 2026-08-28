package relay

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/ifloppy/chat-with-cli/internal/protocol"
)

type Broker struct {
	mu    sync.RWMutex
	peers map[string]*peer
}

type peer struct {
	device    string
	conn      *websocket.Conn
	writeMu   sync.Mutex
	pendingMu sync.Mutex
	pending   map[string]chan protocol.Response
	done      chan struct{}
	doneOnce  sync.Once
}

type RemoteCaller struct {
	Broker *Broker
	Device string
}

func NewBroker() *Broker {
	return &Broker{peers: make(map[string]*peer)}
}

func (c RemoteCaller) Call(ctx context.Context, method string, raw json.RawMessage) (json.RawMessage, error) {
	return c.Broker.Call(ctx, c.Device, method, raw)
}

func (b *Broker) Call(ctx context.Context, device, method string, raw json.RawMessage) (json.RawMessage, error) {
	b.mu.RLock()
	p := b.peers[device]
	b.mu.RUnlock()
	if p == nil {
		return nil, fmt.Errorf("device %q is offline", device)
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
	if err := p.writeJSON(ctx, request); err != nil {
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
	case <-ctx.Done():
		return nil, ctx.Err()
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

func (p *peer) close(reason string) {
	p.doneOnce.Do(func() { close(p.done) })
	_ = p.conn.Close(websocket.StatusNormalClosure, reason)
}

func (b *Broker) AgentHandler(agentToken string) http.HandlerFunc {
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
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			return
		}
		conn.SetReadLimit(32 << 20)
		p := &peer{device: device, conn: conn, pending: make(map[string]chan protocol.Response), done: make(chan struct{})}

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
}

func validBearer(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
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
