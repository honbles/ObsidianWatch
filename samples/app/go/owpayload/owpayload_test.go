package owpayload

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type recorder struct{ spans []sdktrace.ReadOnlySpan }

func (c *recorder) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (c *recorder) OnEnd(s sdktrace.ReadOnlySpan)                   { c.spans = append(c.spans, s) }
func (c *recorder) Shutdown(context.Context) error                  { return nil }
func (c *recorder) ForceFlush(context.Context) error                { return nil }

func TestBody(t *testing.T) {
	c := &recorder{}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(c))
	var got string
	h := Middleware("/login")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); got = string(b) }))
	for _, p := range []string{"/items?x=1", "/login"} {
		ctx, span := tp.Tracer("t").Start(context.Background(), p)
		req := httptest.NewRequest("POST", p, strings.NewReader(`{"a":{"b":1}}`)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(httptest.NewRecorder(), req)
		span.End()
		if got != `{"a":{"b":1}}` {
			t.Fatal("body not passed on", got)
		}
	}
	attrs := func(i int) map[string]string {
		m := map[string]string{}
		for _, a := range c.spans[i].Attributes() {
			m[string(a.Key)] = a.Value.AsString()
		}
		return m
	}
	if a := attrs(0); a["url.query"] != "x=1" || a["ow.request.body"] != `{"a":{"b":1}}` {
		t.Fatalf("items %v", a)
	}
	if a := attrs(1); len(a) != 0 {
		t.Fatalf("login %v", a)
	}
}
