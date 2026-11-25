//go:build !darwin

package otel

import "net"

// otherResolver cannot identify the sending process on this platform yet, so every
// connection is reported unresolved and telemetry is marked "asserted" (it can never
// raise high-severity alerts on its own). Process identification for this OS is a
// known gap; see docs/application/capability.md.
type otherResolver struct{}

// NewPeerResolver returns the fallback resolver.
func NewPeerResolver() PeerResolver { return otherResolver{} }

func (otherResolver) Resolve(net.Conn) Peer {
	return Peer{Reason: "process identification is not implemented on this platform"}
}
