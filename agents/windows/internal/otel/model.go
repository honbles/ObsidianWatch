package otel

// model.go - the decoded, allowlisted form of OTLP data. Only attributes in the
// allowlists below survive decoding; everything else is dropped at the agent, which
// also controls cardinality and personal data (spec sections 7 and 12).

import (
	"strconv"
	"strings"
)

// Span kinds (OTLP SpanKind).
const (
	kindInternal = 1
	kindServer   = 2
	kindClient   = 3
	kindProducer = 4
	kindConsumer = 5
)

// OTLP status codes.
const (
	statusUnset = 0
	statusOK    = 1
	statusError = 2
)

// Resource is the allowlisted subset of resource attributes. host.*, container.*
// and k8s.* are deliberately absent: the agent stamps those itself and never trusts
// what an application says about where it runs.
type Resource struct {
	Service     string
	Environment string
	InstanceRef string // service.instance.id
	Version     string // service.version
	Language    string // telemetry.sdk.language
	SDK         string // telemetry.sdk.name + version
}

// Span is one decoded span, allowlisted.
type Span struct {
	Res        Resource
	TraceID    string // lower-case hex
	SpanID     string
	ParentID   string
	Name       string
	Kind       int
	StartNano  uint64
	EndNano    uint64
	StatusCode int

	Route       string // http.route (template)
	Method      string // http.request.method / http.method
	HTTPStatus  int    // http.response.status_code / http.status_code
	ClientAddr  string // client.address
	PeerAddr    string // network.peer.address
	DBSystem    string
	ServerAddr  string // server.address
	ServerPort  int
	PeerService string
	Messaging   string // messaging.system
	EndUser     string // enduser.id (hashed before leaving the receiver)
	ExcType     string // exception.type, from an "exception" span event
}

// Log is one decoded log record (helper events, spec section 9).
type Log struct {
	Res       Resource
	TimeNano  uint64
	EventName string
	TraceID   string
	SpanID    string
	Attrs     map[string]string // allowlisted helper fields
}

// Durations in milliseconds.
func (s *Span) DurationMs() float64 {
	if s.EndNano <= s.StartNano {
		return 0
	}
	return float64(s.EndNano-s.StartNano) / 1e6
}

// EndUnset reports a span that carries no timing at all (cannot be aggregated).
func (s *Span) EndUnset() bool { return s.StartNano == 0 && s.EndNano == 0 }

// IsError reports whether the span failed: an explicit error status or an HTTP 5xx.
func (s *Span) IsError() bool { return s.StatusCode == statusError || s.HTTPStatus >= 500 }

var resourceAllow = map[string]bool{
	"service.name": true, "deployment.environment": true, "deployment.environment.name": true,
	"service.instance.id": true, "service.version": true,
	"telemetry.sdk.language": true, "telemetry.sdk.name": true, "telemetry.sdk.version": true,
}

var spanAllow = map[string]bool{
	"http.route": true, "http.request.method": true, "http.method": true,
	"http.response.status_code": true, "http.status_code": true,
	"client.address": true, "network.peer.address": true,
	// older semantic conventions, still sent by many SDK versions (Node 0.5x, Java agent 1.x, .NET opt-out)
	"http.client_ip": true, "net.peer.ip": true, "net.sock.peer.addr": true, "client.socket.address": true,
	"db.system": true, "server.address": true, "server.port": true, "peer.service": true,
	"messaging.system": true, "enduser.id": true, "exception.type": true,
}

// helperAllow lists the helper-event fields (spec section 9) that may leave the agent.
// Bodies, parameter values and headers are never in this list.
var helperAllow = map[string]bool{
	"outcome": true, "method": true, "user": true, "reason": true, "mfa": true,
	"resource_type": true, "action": true, "route": true, "policy": true,
	"kind": true, "parameter": true, "target_host": true, "type_name": true,
	"limit_name": true, "target_type": true, "target_id": true,
	"rows": true, "bytes": true, "format": true,
	"session": true, "object_type": true, "object_id": true, "helper_version": true,
	"client.address": true, "network.peer.address": true, "enduser.id": true,
}

// helperEvents are the event.name values the helper may emit.
var helperEvents = map[string]bool{
	"auth.login": true, "auth.mfa": true, "authz.deny": true, "input.rejected": true,
	"ssrf.blocked": true, "deserialization.blocked": true, "ratelimit.hit": true,
	"admin.action": true, "data.export": true, "session.anomaly": true, "data.access": true,
}

// attrValue is a decoded AnyValue reduced to what we use.
type attrValue struct {
	s     string
	i     int64
	isInt bool
}

func (v attrValue) str() string {
	if v.isInt {
		return strconv.FormatInt(v.i, 10)
	}
	return v.s
}

func (v attrValue) num() (int64, bool) {
	if v.isInt {
		return v.i, true
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(v.s), 10, 64); err == nil {
		return n, true
	}
	return 0, false
}

func (r *Resource) set(k string, v attrValue) {
	switch k {
	case "service.name":
		r.Service = v.str()
	case "deployment.environment", "deployment.environment.name":
		if r.Environment == "" || k == "deployment.environment.name" {
			r.Environment = v.str()
		}
	case "service.instance.id":
		r.InstanceRef = v.str()
	case "service.version":
		r.Version = v.str()
	case "telemetry.sdk.language":
		r.Language = v.str()
	case "telemetry.sdk.name":
		if !strings.Contains(r.SDK, v.str()) {
			r.SDK = strings.TrimSpace(v.str() + " " + r.SDK)
		}
	case "telemetry.sdk.version":
		r.SDK = strings.TrimSpace(r.SDK + " " + v.str())
	}
}

func (s *Span) set(k string, v attrValue) {
	switch k {
	case "http.route":
		s.Route = v.str()
	case "http.request.method", "http.method":
		s.Method = strings.ToUpper(v.str())
	case "http.response.status_code", "http.status_code":
		if n, ok := v.num(); ok {
			s.HTTPStatus = int(n)
		}
	case "client.address":
		s.ClientAddr = v.str()
	case "http.client_ip": // old name for the client address (set from X-Forwarded-For); never overrides client.address
		if s.ClientAddr == "" {
			s.ClientAddr = v.str()
		}
	case "network.peer.address", "net.sock.peer.addr", "client.socket.address", "net.peer.ip":
		if s.PeerAddr == "" || k == "network.peer.address" {
			s.PeerAddr = v.str()
		}
	case "db.system":
		s.DBSystem = v.str()
	case "server.address":
		s.ServerAddr = v.str()
	case "server.port":
		if n, ok := v.num(); ok {
			s.ServerPort = int(n)
		}
	case "peer.service":
		s.PeerService = v.str()
	case "messaging.system":
		s.Messaging = v.str()
	case "enduser.id":
		s.EndUser = v.str()
	case "exception.type":
		s.ExcType = v.str()
	}
}
