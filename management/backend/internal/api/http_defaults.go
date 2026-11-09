package api

import (
	"io"
	"net/http"
	"time"
)

// outboundTimeout bounds every outbound call made through http.DefaultClient
// (cloud, DevOps, NVD, OSV connectors). Without it a stalled upstream holds the
// calling goroutine, and the sync job that owns it, indefinitely. Callers that
// need a tighter limit still pass a context deadline.
const outboundTimeout = 90 * time.Second

// maxOutboundBody caps how much of any upstream response we will read. Large
// legitimate payloads (GitHub trees, asset inventories) are far below this; a
// hostile or broken upstream streaming without end is cut off here instead of
// exhausting memory in io.ReadAll / json.Decode.
const maxOutboundBody = 64 << 20

type cappedBodyTransport struct {
	next  http.RoundTripper
	limit int64
}

type limitedBody struct {
	io.Reader
	io.Closer
}

func (t cappedBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = limitedBody{Reader: io.LimitReader(resp.Body, t.limit), Closer: resp.Body}
	return resp, nil
}

func init() {
	if http.DefaultClient.Timeout == 0 {
		http.DefaultClient.Timeout = outboundTimeout
	}
	if _, ok := http.DefaultClient.Transport.(cappedBodyTransport); !ok {
		next := http.DefaultClient.Transport
		if next == nil {
			next = newGuardedTransport() // SSRF guard, see outbound_guard.go
		}
		http.DefaultClient.Transport = cappedBodyTransport{next: next, limit: maxOutboundBody}
	}
}
