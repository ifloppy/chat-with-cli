package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
)

// Request is the small RPC envelope used between relay and device agents.
type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Args   json.RawMessage `json:"args,omitempty"`
}

// Response is returned by an agent for exactly one Request.
type Response struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
