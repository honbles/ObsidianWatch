// Package owpayload reports request fields to the ObsidianWatch agent
// (optional): the query string as url.query and a JSON request body as
// ow.request.body on the server span, so the console lists each route's
// parameters and, once an administrator has reviewed a route, shows sampled
// values (never credential-like ones). Put Middleware inside the otelhttp
// handler so the server span is in the request context.
package owpayload

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// MaxBody is the largest body reported (the agent's limit).
const MaxBody = 32 << 10

// Middleware records the fields and hands the handler the whole body.
// skip lists path prefixes whose bodies are never reported (sign-in and
// password routes, for example); their query strings are not reported either.
func Middleware(skip ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			record(r, skip)
			next.ServeHTTP(w, r)
		})
	}
}

func record(r *http.Request, skip []string) {
	span := trace.SpanFromContext(r.Context())
	if !span.IsRecording() {
		return
	}
	for _, p := range skip {
		if strings.HasPrefix(r.URL.Path, p) {
			return
		}
	}
	if r.URL.RawQuery != "" {
		span.SetAttributes(attribute.String("url.query", r.URL.RawQuery))
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if r.Body == nil || (ct != "" && !strings.HasPrefix(ct, "application/json")) || r.ContentLength > MaxBody {
		return
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
	if err != nil || len(buf) == 0 || len(buf) > MaxBody {
		return
	}
	if t := bytes.TrimSpace(buf); len(t) > 0 && t[0] == '{' && json.Valid(t) {
		span.SetAttributes(attribute.String("ow.request.body", string(t)))
	}
}
