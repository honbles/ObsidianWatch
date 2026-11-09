package api

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestBlockedOutboundAddr(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "100.127.255.254", "fd00:ec2::254", "224.0.0.1", "::ffff:127.0.0.1", "fe80::1"} {
		if !blockedOutboundAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s should be blocked", a)
		}
	}
	for _, a := range []string{"8.8.8.8", "10.1.2.3", "192.168.1.5", "172.16.0.9", "2606:4700::1111", "100.63.255.255", "100.128.0.1"} {
		if blockedOutboundAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s should be allowed", a)
		}
	}
}

func TestGuardedTransportBlocksLoopbackAtDial(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("http_proxy", "")
	t.Setenv("OW_ALLOW_INTERNAL_OUTBOUND", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := &http.Client{Transport: newGuardedTransport()}
	if resp, err := c.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("request to a loopback server must be blocked by the dial guard")
	}
	t.Setenv("OW_ALLOW_INTERNAL_OUTBOUND", "true")
	c2 := &http.Client{Transport: newGuardedTransport()}
	resp, err := c2.Get(srv.URL)
	if err != nil {
		t.Fatalf("override must allow loopback: %v", err)
	}
	resp.Body.Close()
}
