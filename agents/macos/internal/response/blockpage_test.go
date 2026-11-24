package response

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func TestBlockPageEndToEnd(t *testing.T) {
	server := netip.MustParseAddr("10.20.30.40")
	var bp blockPage
	httpAddr, dnsAddr := freeAddr(t), freeAddr(t)
	ok, err := bp.start(httpAddr, dnsAddr, map[string][]netip.Addr{"SIEM.Example.com.": {server}}, "web-01")
	if err != nil || !ok {
		t.Fatalf("start: %v %v", ok, err)
	}
	defer bp.stop()

	for _, network := range []string{"udp", "tcp"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, dnsAddr)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		got, err := r.LookupNetIP(ctx, "ip4", "evil.example.org")
		cancel()
		if err != nil || len(got) != 1 || got[0] != sinkAddr {
			t.Errorf("%s: any name must resolve to the sink: %v %v", network, got, err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		got, err = r.LookupNetIP(ctx, "ip4", "siem.example.com")
		cancel()
		if err != nil || len(got) != 1 || got[0] != server {
			t.Errorf("%s: the server name must keep its real address: %v %v", network, got, err)
		}
	}

	resp, err := http.Get("http://" + httpAddr + "/anything?x=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 511 || !strings.Contains(string(body), "contact your administrator") || !strings.Contains(string(body), "ObsidianWatch") || !strings.Contains(string(body), "web-01") {
		t.Fatalf("page: %d %s", resp.StatusCode, body)
	}
	bp.stop()
	if _, err := http.Get("http://" + httpAddr + "/"); err == nil {
		t.Error("block page still serving after stop")
	}
}

func TestDNSAnswerEdges(t *testing.T) {
	none := func(string) []netip.Addr { return nil }
	q := func(name string, qtype byte) []byte {
		b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, l := range strings.Split(name, ".") {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
		return append(b, 0, 0, qtype, 0, 1)
	}
	if r := dnsAnswer(q("a.b", 28), none); r == nil || r[7] != 0 {
		t.Error("AAAA must get an empty answer (forces IPv4 to the sink)")
	}
	if r := dnsAnswer(q("a.b", 1), none); r == nil || r[7] != 1 || r[0] != 0x12 || r[1] != 0x34 {
		t.Error("A must get one sink answer with the query id")
	}
	if dnsAnswer([]byte{1, 2, 3}, none) != nil {
		t.Error("short packet answered")
	}
	resp := q("a.b", 1)
	resp[2] |= 0x80
	if dnsAnswer(resp, none) != nil {
		t.Error("a response packet must not be answered (no reflection loops)")
	}
	if !strings.Contains(string(BlockPageHTML(`<script>`, `x"><img>`)), "&lt;script&gt;") {
		t.Error("page does not escape the host name")
	}
}
