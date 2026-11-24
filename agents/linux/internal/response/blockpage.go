package response

// blockpage.go - what a user sees while the host is isolated.
//
// Isolation blocks everything except the ObsidianWatch servers, so a browser
// would just spin. While isolated the agent instead runs two small listeners
// on loopback:
//
//   - a DNS sink: every name resolves to 127.0.0.1 (no IPv6 answers), except
//     the ObsidianWatch server names, which get their real addresses so the
//     agent keeps talking to the server;
//   - an HTTP server that answers every request with a page saying the
//     device is isolated and to contact the administrator.
//
// Each platform points DNS and HTTP at them (blockpage_<os>.go). Plain HTTP
// and the operating system's captive-portal checks land on the page. HTTPS
// sites cannot show it without a certificate warning, so they fail fast
// instead; browsers that fall back to http:// then show the page.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// sinkAddr is where every non-exempt name points while isolated.
var sinkAddr = netip.MustParseAddr("127.0.0.1")

type blockPage struct {
	mu      sync.Mutex
	running bool
	httpSrv *http.Server
	udp     net.PacketConn
	tcp     net.Listener
	exempt  map[string][]netip.Addr
	hostTxt string
}

// start brings up the listeners. A port that cannot be bound (something else
// already listens on it) is reported but does not undo isolation. dnsOK says
// whether the DNS sink is up, so a platform only points DNS at a sink that
// answers.
func (b *blockPage) start(httpAddr, dnsAddr string, exempt map[string][]netip.Addr, hostname string) (dnsOK bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exempt = normaliseExempt(exempt)
	b.hostTxt = hostname
	if b.running {
		return b.udp != nil, nil
	}
	var errs []string
	if ln, err := net.Listen("tcp", httpAddr); err != nil {
		errs = append(errs, "block page: "+err.Error())
	} else {
		b.httpSrv = &http.Server{Handler: http.HandlerFunc(b.serveHTTP), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
		go func() { _ = b.httpSrv.Serve(ln) }()
	}
	if pc, err := net.ListenPacket("udp", dnsAddr); err != nil {
		errs = append(errs, "dns sink (udp): "+err.Error())
	} else {
		b.udp = pc
		go b.serveUDP(pc)
	}
	if ln, err := net.Listen("tcp", dnsAddr); err != nil {
		errs = append(errs, "dns sink (tcp): "+err.Error())
	} else {
		b.tcp = ln
		go b.serveTCP(ln)
	}
	b.running = true
	if len(errs) > 0 {
		return b.udp != nil, errors.New(strings.Join(errs, "; "))
	}
	return true, nil
}

func (b *blockPage) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.httpSrv != nil {
		_ = b.httpSrv.Close()
		b.httpSrv = nil
	}
	if b.udp != nil {
		_ = b.udp.Close()
		b.udp = nil
	}
	if b.tcp != nil {
		_ = b.tcp.Close()
		b.tcp = nil
	}
	b.running = false
}

func (b *blockPage) lookup(name string) []netip.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exempt[name]
}

func normaliseExempt(m map[string][]netip.Addr) map[string][]netip.Addr {
	out := make(map[string][]netip.Addr, len(m))
	for k, v := range m {
		out[strings.TrimSuffix(strings.ToLower(k), ".")] = v
	}
	return out
}

func (b *blockPage) serveHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	host := b.hostTxt
	b.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	// 511 is the status captive-portal checks expect; browsers render the body.
	w.WriteHeader(http.StatusNetworkAuthenticationRequired)
	_, _ = w.Write(BlockPageHTML(host, r.Host))
}

// BlockPageHTML is the page shown on an isolated host.
func BlockPageHTML(hostname, requested string) []byte {
	req := ""
	if requested != "" {
		req = `<p class="small">You tried to open <b>` + html.EscapeString(requested) + `</b>.</p>`
	}
	return []byte(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network access blocked - ObsidianWatch</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1115;color:#e6e8ec;font:15px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.card{max-width:520px;margin:24px;padding:36px 40px;background:#171a21;border:1px solid #2a2f3a;border-radius:12px}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:16px;margin-bottom:28px}
h1{font-size:22px;margin:0 0 12px}p{margin:0 0 12px;color:#b8bdc8}.small{font-size:13px;color:#8a909c}
.tag{display:inline-block;margin-top:8px;padding:3px 10px;border-radius:999px;background:#3a1d1f;color:#ff8f8f;font-size:12px;font-weight:600}
</style></head><body><div class="card">
<div class="brand"><svg width="26" height="26" viewBox="0 0 22 22" aria-hidden="true"><path d="M11 1.5 20 6.5v9L11 20.5 2 15.5v-9z" fill="none" stroke="#4cc2ff" stroke-width="1.8" stroke-linejoin="round"/><circle cx="11" cy="11" r="3" fill="#4cc2ff"/></svg>ObsidianWatch</div>
<h1>This device has been isolated from the network</h1>
<p>Your security team has temporarily blocked network access on this computer while they investigate a security event. Internet and network resources are unavailable.</p>
<p><b>Please contact your administrator or IT help desk.</b> Do not restart or reinstall the device unless they ask you to.</p>` + req + `
<p class="small">Device: ` + html.EscapeString(hostname) + `</p><span class="tag">Isolated by ObsidianWatch</span>
</div></body></html>`)
}

// ── DNS sink ──────────────────────────────────────────────────────────────────

func (b *blockPage) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp := dnsAnswer(buf[:n], b.lookup); resp != nil {
			_, _ = pc.WriteTo(resp, addr)
		}
	}
}

func (b *blockPage) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(c)
			for {
				var l uint16
				if err := binary.Read(r, binary.BigEndian, &l); err != nil {
					return
				}
				q := make([]byte, l)
				if _, err := io.ReadFull(r, q); err != nil {
					return
				}
				resp := dnsAnswer(q, b.lookup)
				if resp == nil {
					return
				}
				out := make([]byte, 2, 2+len(resp))
				binary.BigEndian.PutUint16(out, uint16(len(resp)))
				if _, err := c.Write(append(out, resp...)); err != nil {
					return
				}
			}
		}(c)
	}
}

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsTTL      = 5 // short, so nothing stale survives release
)

// dnsAnswer builds the reply to a single-question query: the exempt
// addresses for a server name, the sink for anything else (A only), and an
// empty NOERROR answer for every other type. Malformed queries get nil.
func dnsAnswer(q []byte, exempt func(string) []netip.Addr) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	name, end, ok := readName(q, 12)
	if !ok || end+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[end : end+2])
	question := q[12 : end+4]

	var addrs []netip.Addr
	if ex := exempt(name); ex != nil {
		for _, a := range ex {
			if (qtype == dnsTypeA && a.Is4()) || (qtype == dnsTypeAAAA && a.Is6() && !a.Is4In6()) {
				addrs = append(addrs, a)
			}
		}
	} else if qtype == dnsTypeA {
		addrs = []netip.Addr{sinkAddr}
	}

	resp := make([]byte, 12, 12+len(question)+len(addrs)*28)
	copy(resp[0:2], q[0:2])
	flags := uint16(0x8180) | uint16(q[2]&0x01)<<8 // QR, RA; echo RD
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(addrs)))
	resp = append(resp, question...)
	for _, a := range addrs {
		rr := []byte{0xC0, 0x0C, 0, 0, 0, 1, 0, 0, 0, dnsTTL, 0, 0}
		binary.BigEndian.PutUint16(rr[2:4], qtype)
		raw := a.AsSlice()
		binary.BigEndian.PutUint16(rr[10:12], uint16(len(raw)))
		resp = append(append(resp, rr...), raw...)
	}
	return resp
}

// readName reads an uncompressed question name starting at off.
func readName(b []byte, off int) (string, int, bool) {
	var labels []string
	for i := 0; i < 128; i++ {
		if off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		off++
		if l == 0 {
			return strings.ToLower(strings.Join(labels, ".")), off, true
		}
		if l&0xC0 != 0 || off+l > len(b) {
			return "", 0, false
		}
		labels = append(labels, string(b[off:off+l]))
		off += l
	}
	return "", 0, false
}

// exemptFor resolves each server hostname to its addresses (IP literals are
// skipped: they need no DNS). cached keeps the last good answer, because
// DNS is blocked once isolation is in place.
func exemptFor(hosts []string, cached map[string][]string, resolve func(string) ([]netip.Addr, error)) (map[string][]netip.Addr, map[string][]string) {
	out := map[string][]netip.Addr{}
	keep := map[string][]string{}
	for _, h := range hosts {
		if _, err := netip.ParseAddr(h); err == nil {
			continue
		}
		var addrs []netip.Addr
		if got, err := resolve(h); err == nil && len(got) > 0 {
			addrs = got
		} else {
			for _, s := range cached[h] {
				if a, err := netip.ParseAddr(s); err == nil {
					addrs = append(addrs, a)
				}
			}
		}
		if len(addrs) == 0 {
			continue
		}
		out[h] = addrs
		for _, a := range addrs {
			keep[h] = append(keep[h], a.String())
		}
	}
	return out, keep
}

func blockPageErr(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf(" (block page partly unavailable: %v)", err)
}
