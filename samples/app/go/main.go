// ObsidianWatch sample application - Go (net/http + OpenTelemetry SDK + owsecurity + owpayload).
// INTENTIONALLY VULNERABLE (fake SQL layer that errors on injection-looking input, and a debug
// endpoint that runs a shell command). Refuses to start unless OW_ALLOW_VULN_DEMO=1 and only binds
// 127.0.0.1. Never deploy it.  Run: OW_ALLOW_VULN_DEMO=1 go run .   (agent receiver on 127.0.0.1:4318)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"ow-sample-go/owpayload"
	"ow-sample-go/owsecurity"
)

// SqlSyntaxError is the exception type the agent groups errors by.
type SqlSyntaxError struct{ msg string }

func (e *SqlSyntaxError) Error() string { return e.msg }

var users = map[string]string{"alice": "correct-horse"}

func main() {
	if os.Getenv("OW_ALLOW_VULN_DEMO") != "1" {
		log.Fatal("This sample is intentionally vulnerable. Set OW_ALLOW_VULN_DEMO=1 to run it (binds 127.0.0.1 only).")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	endpoint := strings.TrimRight(envOr("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"), "/")
	name := envOr("OTEL_SERVICE_NAME", "sample-go")
	attrs := map[string]string{"service.name": name, "deployment.environment.name": "demo", "service.version": "1.0.0"}

	// Traces: the official SDK, OTLP/HTTP protobuf to the agent.
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint+"/v1/traces"))
	if err != nil {
		log.Fatal(err)
	}
	var kv []attribute.KeyValue
	for k, v := range attrs {
		kv = append(kv, attribute.String(k, v))
	}
	res, _ := resource.New(ctx, resource.WithTelemetrySDK(), resource.WithAttributes(kv...))
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exp))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Security events (Tier 2): same service name and environment as the traces.
	stopSec := owsecurity.Init(endpoint+"/v1/logs", attrs)

	mux := http.NewServeMux()
	handle(mux, "GET /health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	handle(mux, "POST /login", login)
	handle(mux, "GET /orders/{orderId}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"id": r.PathValue("orderId"), "status": "shipped"})
	})
	handle(mux, "GET /search", search)
	handle(mux, "GET /debug/exec", debugExec)

	// otelhttp makes the server span; owpayload (inside it) reports url.query and the
	// JSON body. /login is skipped: its body carries the password.
	h := otelhttp.NewHandler(owpayload.Middleware("/login")(clientAddress(mux)), "http.server")
	srv := &http.Server{Addr: "127.0.0.1:" + envOr("PORT", "5004"), Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	stopSec()
	_ = tp.Shutdown(sctx)
}

// handle registers a route and names the server span after its template, so the
// console shows /orders/{orderId} rather than every order id.
func handle(mux *http.ServeMux, pattern string, fn http.HandlerFunc) {
	method, route, _ := strings.Cut(pattern, " ")
	mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		span.SetName(method + " " + route)
		span.SetAttributes(attribute.String("http.route", route))
		fn(w, r)
	}))
}

// clientAddress records the client and peer address on the server span.
func clientAddress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("client.address", ip), attribute.String("network.peer.address", ip))
		next.ServeHTTP(w, r)
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	var b struct{ User, Password string }
	_ = json.NewDecoder(r.Body).Decode(&b)
	if p, ok := users[b.User]; ok && p == b.Password && b.Password != "" {
		owsecurity.Login(r.Context(), "success", b.User, clientIP(r), "/login", "password", "")
		writeJSON(w, 200, map[string]any{"token": "demo-token"})
		return
	}
	owsecurity.Login(r.Context(), "failure", b.User, clientIP(r), "/login", "password", "invalid_credentials")
	writeJSON(w, 401, map[string]any{"error": "invalid credentials"})
}

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if strings.Contains(q, "'") || strings.Contains(q, "--") || strings.Contains(strings.ToLower(q), " or ") {
		owsecurity.InputRejected(r.Context(), "sqli", "/search", "q", clientIP(r))
		err := &SqlSyntaxError{"syntax error near the supplied search text"}
		span := trace.SpanFromContext(r.Context())
		span.RecordError(err, trace.WithStackTrace(true))
		span.SetStatus(codes.Error, err.Error())
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"results": []any{}})
}

// Intentionally vulnerable: runs a command given by the caller (rule APP-H01 should fire).
func debugExec(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if cmd == "" {
		cmd = "id"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "/bin/sh", "-c", cmd).Output()
	if len(out) > 500 {
		out = out[:500]
	}
	writeJSON(w, 200, map[string]any{"output": string(out)})
}

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
