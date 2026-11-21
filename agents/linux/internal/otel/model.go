package otel

// model.go - the decoded, allowlisted form of OTLP data. Only attributes in the
// allowlists below survive decoding; everything else is dropped at the agent, which
// also controls cardinality and personal data (spec sections 7 and 12).

import (
	"net/url"
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
	Signature   string // injection class found in a parameter value ("param.sql-injection"), never the value

	// ParamNames are the query-string parameter NAMES of the request, never values. The raw query string
	// is parsed where it is decoded and discarded; nothing but these names is kept (payload design, step 1).
	ParamNames []string
	// ParamValues holds the decoded values for the request's parameters, in memory only, so that a route
	// whose parameters an admin has reviewed can forward the allowed ones. Ingest clears it as soon as the
	// span has been aggregated; it is never serialised, logged or buffered with the trace.
	ParamValues map[string]string
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
	// Read only to extract parameter names; the value of these attributes is never stored or forwarded.
	"url.query": true, "http.target": true, "http.url": true, "ow.request.body": true,
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
	case "url.query":
		s.addQuery(v.str())
	case bodyAttr:
		s.addBody(v.str())
	case "http.target", "http.url": // old conventions: path plus query, or the full URL
		if i := strings.IndexByte(v.str(), '?'); i >= 0 {
			s.addQuery(v.str()[i+1:])
		}
	}
}

func (s *Span) addQuery(q string) {
	names, vals := queryParams(q)
	s.ParamNames = mergeParamNames(s.ParamNames, names)
	if len(vals) > 0 && s.ParamValues == nil {
		s.ParamValues = map[string]string{}
	}
	for k, v := range vals {
		if _, ok := s.ParamValues[k]; !ok {
			s.ParamValues[k] = v
		}
	}
}

const (
	maxParamValueLen = 256
	maxParamNameLen  = 64
	maxParamsPerSpan = 50
)

// QueryParamNames returns the parameter names of a query string, de-duplicated, in order. Values are
// discarded. Entries that do not look like a parameter name are skipped, so a bare token placed in the
// query ("?3f9a...") is not mistaken for a name and forwarded.
func QueryParamNames(q string) []string {
	names, _ := queryParams(q)
	return names
}

// queryParams parses a query string into the parameter names (in order, de-duplicated) and the first
// decoded value of each, capped in length.
func queryParams(q string) ([]string, map[string]string) {
	if i := strings.IndexByte(q, '#'); i >= 0 {
		q = q[:i]
	}
	var out []string
	vals := map[string]string{}
	for _, part := range strings.Split(q, "&") {
		if part == "" {
			continue
		}
		name, value, hasValue := part, "", false
		if i := strings.IndexByte(part, '='); i >= 0 {
			name, value, hasValue = part[:i], part[i+1:], true
		}
		u, err := url.QueryUnescape(name)
		if err != nil {
			continue
		}
		name = strings.TrimSpace(u)
		if !validParamName(name) || (!hasValue && len(name) > 32) {
			continue
		}
		if _, dup := vals[name]; dup {
			continue
		}
		if uv, err := url.QueryUnescape(value); err == nil {
			value = uv
		}
		if len(value) > maxParamValueLen {
			value = value[:maxParamValueLen]
		}
		vals[name] = value
		out = append(out, name)
		if len(out) >= maxParamsPerSpan {
			break
		}
	}
	return out, vals
}

func validParamName(n string) bool {
	if n == "" || len(n) > maxParamNameLen {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.', c == '[', c == ']':
		default:
			return false
		}
	}
	return true
}

func mergeParamNames(have, add []string) []string {
	for _, n := range add {
		dup := false
		for _, h := range have {
			if h == n {
				dup = true
				break
			}
		}
		if !dup && len(have) < maxParamsPerSpan {
			have = append(have, n)
		}
	}
	return have
}

// Parameter names that are never forwarded, whatever an admin chooses. Matching works on the whole name with
// separators removed (apiKey, api_key, API-KEY) and on the words inside it (user_password, authToken).
var deniedCompact = []string{"password", "passwd", "passphrase", "secret", "token", "apikey", "authorization", "cookie",
	"creditcard", "cardnumber", "cvv", "cvc", "sessionid", "privatekey", "accesskey", "clientsecret", "refreshtoken"}

var deniedWords = map[string]bool{"pwd": true, "pass": true, "jwt": true, "bearer": true, "auth": true, "sid": true, "otp": true,
	"pin": true, "ssn": true, "card": true, "pan": true, "iban": true, "cvv": true, "cvc": true, "signature": true, "sig": true,
	"credential": true, "credentials": true, "session": true, "sess": true, "csrf": true, "xsrf": true, "secret": true, "token": true,
	"password": true, "passwd": true, "cookie": true}

// PayloadNameDenied reports whether a parameter name belongs to the always-masked set.
func PayloadNameDenied(name string) bool {
	var compact strings.Builder
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	var prev rune
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			compact.WriteRune(r)
			cur = append(cur, r)
		case r >= 'A' && r <= 'Z':
			compact.WriteRune(r + 32)
			if prev >= 'a' && prev <= 'z' { // camelCase boundary
				flush()
			}
			cur = append(cur, r)
		default:
			flush()
		}
		prev = r
	}
	flush()
	c := compact.String()
	for _, d := range deniedCompact {
		if strings.Contains(c, d) {
			return true
		}
	}
	for _, w := range words {
		if deniedWords[w] {
			return true
		}
	}
	return false
}

// PayloadValueMasked reports whether a value looks like a credential or a card number and must not be
// forwarded even from an allowed parameter: JWTs, bearer or basic credentials, private keys, long opaque
// tokens, and card numbers (Luhn).
func PayloadValueMasked(v string) bool {
	t := strings.TrimSpace(v)
	if t == "" {
		return false
	}
	l := strings.ToLower(t)
	if strings.HasPrefix(l, "bearer ") || strings.HasPrefix(l, "basic ") || strings.Contains(t, "-----BEGIN") {
		return true
	}
	if strings.HasPrefix(t, "eyJ") && strings.Count(t, ".") == 2 {
		return true
	}
	digits, ok := 0, true
	for _, r := range t {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == ' ' || r == '-':
		default:
			ok = false
		}
	}
	if ok && digits >= 13 && digits <= 19 && luhn(t) {
		return true
	}
	if len(t) >= 32 && !strings.ContainsAny(t, " \t") {
		hasD, hasL, clean := false, false, true
		for _, r := range t {
			switch {
			case r >= '0' && r <= '9':
				hasD = true
			case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
				hasL = true
			case r == '+' || r == '/' || r == '_' || r == '=' || r == '-' || r == '.':
			default:
				clean = false
			}
		}
		if clean && hasD && hasL {
			return true
		}
	}
	return false
}

func luhn(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}
