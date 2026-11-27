package telemetry

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP returns the caller's address. Forwarding headers are honoured only when the direct peer is a
// private or loopback address, that is our own reverse proxy (the console's nginx overwrites both headers
// with the address it sees, so a client cannot supply them). In X-Forwarded-For the right-most public entry
// is used, because a client can prepend anything on the left; X-Real-IP is used when there is no
// X-Forwarded-For. Without this, audit entries, security events and the per-IP login limiter would all see
// the proxy's address, and anyone could rotate the header to dodge the limiter.
func ClientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	pa, err := netip.ParseAddr(peer)
	if err != nil {
		return peer
	}
	pa = pa.Unmap()
	if !(pa.IsPrivate() || pa.IsLoopback()) {
		return pa.String()
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
			return a.Unmap().String()
		}
		return pa.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		if a = a.Unmap(); a.IsPrivate() || a.IsLoopback() {
			continue
		}
		return a.String()
	}
	// Every hop was private (an internal client behind our proxy): the left-most valid entry.
	for _, p := range parts {
		if a, err := netip.ParseAddr(strings.TrimSpace(p)); err == nil {
			return a.Unmap().String()
		}
	}
	return pa.String()
}
