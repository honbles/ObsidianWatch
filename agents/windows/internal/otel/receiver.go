package otel

// receiver.go - the OTLP/HTTP receiver. It binds ONLY to loopback or a Unix socket,
// never to a routable address, and never opens an inbound port on the network. For each
// connection it identifies the sending process and stamps identity itself; any host,
// container or process identity the application claims is ignored (spec sections 3, 4, 7).

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

const (
	maxRequestBytes      = 4 << 20  // compressed body
	maxDecompressedBytes = 16 << 20 // after gzip
)

// ReceiverOptions configures where and how the receiver listens.
type ReceiverOptions struct {
	Listen     string      // "127.0.0.1:4318"; empty disables TCP
	Socket     string      // Unix socket path; empty disables
	SocketMode os.FileMode // default 0666: identity comes from SO_PEERCRED, not file permissions
}

// RecvStats are counters for health reporting.
type RecvStats struct {
	Requests, BadRequests, Spans, Logs, SecurityEvents, Asserted, Unresolved, EmitDropped atomic.Int64
}

type Receiver struct {
	opt      ReceiverOptions
	agg      *Aggregator
	binder   *Binder
	resolver PeerResolver
	ec       EventContext
	emit     func(schema.Event) bool
	log      *slog.Logger
	mu       sync.RWMutex // guards srvs and lns (Addrs/OnlyLocal may run while Start is appending)
	srvs     []*http.Server
	lns      []net.Listener
	Stats    RecvStats
}

func NewReceiver(opt ReceiverOptions, agg *Aggregator, binder *Binder, resolver PeerResolver, ec EventContext,
	emit func(schema.Event) bool, logger *slog.Logger) *Receiver {
	if opt.SocketMode == 0 {
		opt.SocketMode = 0o666
	}
	return &Receiver{opt: opt, agg: agg, binder: binder, resolver: resolver, ec: ec, emit: emit, log: logger}
}

// ValidateListen rejects any TCP address that is not a loopback IP literal.
func ValidateListen(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("otlp listen %q: %w", addr, err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	if !IsLoopbackAddr(host) {
		return "", fmt.Errorf("otlp listen %q: must be a loopback address (127.0.0.0/8 or ::1); the receiver never binds a routable address", addr)
	}
	return net.JoinHostPort(host, port), nil
}

type connKeyT struct{}

// lazyPeer resolves the sending process once per connection, on first use.
type lazyPeer struct {
	once sync.Once
	conn net.Conn
	res  PeerResolver
	peer Peer
}

func (l *lazyPeer) get() Peer {
	l.once.Do(func() { l.peer = l.res.Resolve(l.conn) })
	return l.peer
}

// Start opens the listeners and serves until ctx is cancelled.
func (r *Receiver) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/traces", r.handle("traces"))
	mux.HandleFunc("POST /v1/logs", r.handle("logs"))
	mux.HandleFunc("POST /v1/metrics", r.handle("metrics"))

	if r.opt.Listen == "" && r.opt.Socket == "" {
		return errors.New("otlp: neither listen address nor socket configured")
	}
	if r.opt.Listen != "" {
		addr, err := ValidateListen(r.opt.Listen)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("otlp listen: %w", err)
		}
		if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() { // defence in depth: verify what was actually bound
			ln.Close()
			return fmt.Errorf("otlp listener bound to non-loopback %s", ln.Addr())
		}
		r.mu.Lock()
		r.lns = append(r.lns, ln)
		r.mu.Unlock()
	}
	if r.opt.Socket != "" {
		if fi, err := os.Lstat(r.opt.Socket); err == nil && fi.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(r.opt.Socket) // stale socket from a previous run
		}
		ln, err := net.Listen("unix", r.opt.Socket)
		if err != nil {
			r.closeAll()
			return fmt.Errorf("otlp unix socket: %w", err)
		}
		_ = os.Chmod(r.opt.Socket, r.opt.SocketMode)
		r.mu.Lock()
		r.lns = append(r.lns, ln)
		r.mu.Unlock()
	}
	r.mu.RLock()
	lns := append([]net.Listener(nil), r.lns...)
	r.mu.RUnlock()
	for _, ln := range lns {
		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, connKeyT{}, &lazyPeer{conn: c, res: r.resolver})
			},
		}
		r.mu.Lock()
		r.srvs = append(r.srvs, srv)
		r.mu.Unlock()
		go func(srv *http.Server, ln net.Listener) {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				r.log.Error("otlp receiver stopped", "err", err)
			}
		}(srv, ln)
		r.log.Info("otlp receiver listening", "addr", ln.Addr().String())
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		r.mu.RLock()
		srvs := append([]*http.Server(nil), r.srvs...)
		r.mu.RUnlock()
		for _, s := range srvs {
			_ = s.Shutdown(sctx)
		}
		if r.opt.Socket != "" {
			_ = os.Remove(r.opt.Socket)
		}
	}()
	return nil
}

func (r *Receiver) closeAll() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ln := range r.lns {
		ln.Close()
	}
}

// Addrs returns the bound listener addresses (tests and health output).
func (r *Receiver) Addrs() []net.Addr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []net.Addr
	for _, ln := range r.lns {
		out = append(out, ln.Addr())
	}
	return out
}

// OnlyLocal reports whether every bound listener is loopback or a Unix socket. The
// agent's health check uses it: a false here must never be ignored.
func (r *Receiver) OnlyLocal() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ln := range r.lns {
		switch a := ln.Addr().(type) {
		case *net.TCPAddr:
			if !a.IP.IsLoopback() {
				return false
			}
		case *net.UnixAddr:
		default:
			return false
		}
	}
	return len(r.lns) > 0
}

func (r *Receiver) handle(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.Stats.Requests.Add(1)
		ct := strings.ToLower(strings.TrimSpace(strings.SplitN(req.Header.Get("Content-Type"), ";", 2)[0]))
		isJSON := ct == "application/json"
		if !isJSON && ct != "application/x-protobuf" {
			r.Stats.BadRequests.Add(1)
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		body, status, err := readBody(w, req)
		if err != nil {
			r.Stats.BadRequests.Add(1)
			http.Error(w, err.Error(), status)
			return
		}
		lp, _ := req.Context().Value(connKeyT{}).(*lazyPeer)
		var peer Peer
		if lp != nil && kind != "metrics" {
			peer = lp.get()
		}
		if !peer.Resolved && kind != "metrics" {
			r.Stats.Unresolved.Add(1)
		}
		now := time.Now()
		switch kind {
		case "traces":
			var spans []Span
			if isJSON {
				spans, err = DecodeTracesJSON(body)
			} else {
				spans, err = DecodeTracesPB(body)
			}
			if err != nil {
				r.Stats.BadRequests.Add(1)
				http.Error(w, "invalid OTLP traces", http.StatusBadRequest)
				return
			}
			ids := map[svcKey]string{}
			for _, s := range spans {
				k := svcKey{s.Res.Service, envOf(s.Res.Environment)}
				id, ok := ids[k]
				if !ok {
					id = r.binder.Bind(k.name, k.env, peer)
					ids[k] = id
					if id == IdentityAsserted {
						r.Stats.Asserted.Add(1)
					}
				}
				if s.EndUnset() {
					continue
				}
				r.agg.Ingest(s, peer, id)
			}
			r.Stats.Spans.Add(int64(len(spans)))
		case "logs":
			var logs []Log
			if isJSON {
				logs, err = DecodeLogsJSON(body)
			} else {
				logs, err = DecodeLogsPB(body)
			}
			if err != nil {
				r.Stats.BadRequests.Add(1)
				http.Error(w, "invalid OTLP logs", http.StatusBadRequest)
				return
			}
			for _, l := range logs {
				id := r.binder.Bind(l.Res.Service, envOf(l.Res.Environment), peer)
				ev, ok := BuildSecurityEvent(l, peer, id, r.ec, now)
				if !ok {
					continue
				}
				r.agg.MarkSecurity(l.TraceID)
				// The normal event channel: enrichment, normalisation, own-activity filter, rate limit.
				if r.emit != nil && !r.emit(ev) {
					r.Stats.EmitDropped.Add(1)
					continue
				}
				r.Stats.SecurityEvents.Add(1)
			}
			r.Stats.Logs.Add(int64(len(logs)))
		}
		// Success: an empty Export*ServiceResponse in the request's own encoding.
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}
}

// readBody reads the (optionally gzip-compressed) request body under hard caps.
func readBody(w http.ResponseWriter, req *http.Request) ([]byte, int, error) {
	var src io.Reader = http.MaxBytesReader(w, req.Body, maxRequestBytes)
	switch strings.ToLower(req.Header.Get("Content-Encoding")) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(src)
		if err != nil {
			return nil, http.StatusBadRequest, errors.New("invalid gzip body")
		}
		defer gz.Close()
		src = gz
	default:
		return nil, http.StatusUnsupportedMediaType, errors.New("unsupported content encoding")
	}
	b, err := io.ReadAll(io.LimitReader(src, maxDecompressedBytes+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, http.StatusRequestEntityTooLarge, errors.New("request too large")
		}
		return nil, http.StatusBadRequest, errors.New("unreadable body")
	}
	if len(b) > maxDecompressedBytes {
		return nil, http.StatusRequestEntityTooLarge, errors.New("request too large")
	}
	return b, 0, nil
}
