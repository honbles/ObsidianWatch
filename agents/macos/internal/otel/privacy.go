package otel

// privacy.go - personal data controls applied before anything leaves the agent:
// user identifiers are hashed with a per-organization HMAC key (spec section 9);
// client addresses can be truncated or dropped per service (spec sections 7 and 12).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
)

// Client address storage modes.
const (
	ClientIPFull      = "full"
	ClientIPTruncated = "truncated"
	ClientIPOff       = "off"
)

// Hasher turns identifiers into stable pseudonyms. With no key it refuses to emit
// anything: an unkeyed hash of an e-mail address is trivially reversible.
type Hasher struct{ key []byte }

func NewHasher(key string) *Hasher { return &Hasher{key: []byte(key)} }

// Enabled reports whether identifiers can be emitted at all.
func (h *Hasher) Enabled() bool { return len(h.key) > 0 }

// Hash returns a 16-hex-digit pseudonym ("" for an empty identifier or no key).
func (h *Hasher) Hash(id string) string {
	if id == "" || len(h.key) == 0 {
		return ""
	}
	m := hmac.New(sha256.New, h.key)
	m.Write([]byte(id))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// ApplyClientIP returns the address to store under the given mode.
func ApplyClientIP(addr, mode string) string {
	if addr == "" || mode == ClientIPOff {
		return ""
	}
	if mode != ClientIPTruncated {
		return addr
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}
