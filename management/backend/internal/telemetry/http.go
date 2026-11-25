package telemetry

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
)

// Middleware records a server span for each request. route returns the route
// template ("/api/v1/alerts/{id}"); requests it cannot place use "other".
// WebSocket upgrades are not traced (they are long-lived, not requests).
func Middleware(route func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !Enabled() || strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				next.ServeHTTP(w, r)
				return
			}
			rt := "other"
			if route != nil {
				if v := route(r); v != "" {
					rt = v
				}
			}
			ctx, span := StartRemote(r.Context(), r.Method+" "+rt, r.Header.Get("traceparent"))
			if span == nil {
				next.ServeHTTP(w, r)
				return
			}
			span.Set("http.request.method", r.Method)
			span.Set("http.route", rt)
			peer := hostOnly(r.RemoteAddr)
			span.Set("network.peer.address", peer)
			client := peer
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				client = strings.TrimSpace(strings.Split(xff, ",")[0])
			}
			span.Set("client.address", client)
			ctx = context.WithValue(ctx, reqKey{}, reqInfo{route: rt, client: client, peer: peer})
			sw := &statusWriter{ResponseWriter: w}
			defer func() {
				if p := recover(); p != nil {
					span.RecordException(fmt.Sprintf("panic: %T", p), fmt.Sprint(p), string(debug.Stack()))
					span.Set("http.response.status_code", 500)
					span.End()
					panic(p)
				}
				code := sw.code
				if code == 0 {
					code = http.StatusOK
				}
				span.Set("http.response.status_code", code)
				if code >= 500 {
					span.SetError(http.StatusText(code))
				}
				span.End()
			}()
			next.ServeHTTP(sw, r.WithContext(ctx))
		})
	}
}

type reqKey struct{}

// reqInfo is what security events raised inside a request inherit.
type reqInfo struct{ route, client, peer string }

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// RouteOf strips the method from a ServeMux pattern ("GET /a/{id}" -> "/a/{id}").
func RouteOf(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		pattern = pattern[i+1:]
	}
	if j := strings.IndexByte(pattern, '/'); j > 0 { // host-qualified pattern
		pattern = pattern[j:]
	}
	return pattern
}

// statusWriter remembers the status code and keeps the optional interfaces.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) {
	if w.code == 0 {
		w.code = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// StartJob begins the root span of a background job (shown on the Jobs tab).
// A job with a parent in ctx is recorded as a child span.
func StartJob(ctx context.Context, name string) (context.Context, *Span) {
	ctx, s := Start(ctx, name, KindInternal)
	s.Set("ow.job.name", name)
	return ctx, s
}
