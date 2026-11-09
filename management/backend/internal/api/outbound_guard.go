package api

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// Outbound SSRF guard. Connector base URLs are validated when saved, but a
// hostname can resolve to (or later be re-pointed at) an internal address, so
// the check that counts is the one made on the address actually being dialled.
// This blocks loopback, link-local (including the 169.254.169.254 cloud
// metadata service), unspecified, multicast, CGNAT 100.64.0.0/10 and the AWS
// IPv6 metadata address for every request that goes through http.DefaultClient.
// RFC1918 ranges stay reachable because self-hosted GitLab/GitHub Enterprise
// commonly lives there.
var (
	guardCGNAT  = netip.MustParsePrefix("100.64.0.0/10")
	awsIMDSv6    = netip.MustParseAddr("fd00:ec2::254")
	guardDisable = func() bool {
		return os.Getenv("OW_ALLOW_INTERNAL_OUTBOUND") == "true"
	}
)

func blockedOutboundAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || guardCGNAT.Contains(a) || a == awsIMDSv6
}

// guardControl is a net.Dialer.Control hook; address is the resolved "ip:port".
func guardControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if blockedOutboundAddr(ip) {
		return fmt.Errorf("outbound connection to %s blocked (internal/metadata address)", ip)
	}
	return nil
}

// proxyConfigured reports whether outbound traffic is routed through an HTTP
// proxy; then the dial target is the proxy itself (often private or loopback)
// and the proxy is the policy point, so the guard is not applied.
func proxyConfigured() bool {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// newGuardedTransport clones the default transport with the dial-time guard.
func newGuardedTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok || guardDisable() || proxyConfigured() {
		return http.DefaultTransport
	}
	t := base.Clone()
	t.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: guardControl}).DialContext
	return t
}
