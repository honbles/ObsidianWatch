package otel

// otlp.go - decoding of OTLP/HTTP export requests (protobuf and JSON) into the
// allowlisted model. Traces and logs are used; metrics are accepted and ignored.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
)

const (
	maxSpansPerRequest = 20000
	maxLogsPerRequest  = 5000
	maxAttrsPerItem    = 256
	maxStringBytes     = 4096
)

var errTooMany = errors.New("otel: too many items in one request")

func clip(s string) string {
	if len(s) > maxStringBytes {
		return s[:maxStringBytes]
	}
	return s
}

// ── protobuf ───────────────────────────────────────────────────────────────

func pbAnyValue(b []byte, depth int) (attrValue, error) {
	var v attrValue
	if depth > pbMaxDepth {
		return v, errPB
	}
	r := &pbReader{b: b}
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return v, err
		}
		switch {
		case f == 1 && w == wireBytes: // string_value
			s, err := r.bytes()
			if err != nil {
				return v, err
			}
			v = attrValue{s: clip(string(s))}
		case f == 2 && w == wireVarint: // bool_value
			x, err := r.varint()
			if err != nil {
				return v, err
			}
			v = attrValue{s: strconv.FormatBool(x != 0)}
		case f == 3 && w == wireVarint: // int_value
			x, err := r.varint()
			if err != nil {
				return v, err
			}
			v = attrValue{i: int64(x), isInt: true}
		case f == 4 && w == wire64: // double_value
			x, err := r.fixed64()
			if err != nil {
				return v, err
			}
			v = attrValue{s: strconv.FormatFloat(math.Float64frombits(x), 'g', -1, 64)}
		default: // arrays, kvlists and bytes are not used by any allowlisted attribute
			if err := r.skip(w); err != nil {
				return v, err
			}
		}
	}
	return v, nil
}

// pbKeyValue decodes one KeyValue message.
func pbKeyValue(b []byte) (string, attrValue, error) {
	r := &pbReader{b: b}
	var key string
	var val attrValue
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return "", val, err
		}
		switch {
		case f == 1 && w == wireBytes:
			k, err := r.bytes()
			if err != nil {
				return "", val, err
			}
			key = string(k)
		case f == 2 && w == wireBytes:
			vb, err := r.bytes()
			if err != nil {
				return "", val, err
			}
			if val, err = pbAnyValue(vb, 0); err != nil {
				return "", val, err
			}
		default:
			if err := r.skip(w); err != nil {
				return "", val, err
			}
		}
	}
	return key, val, nil
}

func pbResource(b []byte) (Resource, error) {
	var res Resource
	r := &pbReader{b: b}
	n := 0
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return res, err
		}
		if f == 1 && w == wireBytes {
			kb, err := r.bytes()
			if err != nil {
				return res, err
			}
			if n++; n > maxAttrsPerItem {
				continue
			}
			k, v, err := pbKeyValue(kb)
			if err != nil {
				return res, err
			}
			if resourceAllow[k] {
				res.set(k, v)
			}
			continue
		}
		if err := r.skip(w); err != nil {
			return res, err
		}
	}
	return res, nil
}

func pbSpan(b []byte, res Resource) (Span, error) {
	s := Span{Res: res}
	r := &pbReader{b: b}
	n := 0
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return s, err
		}
		switch {
		case f == 1 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return s, err
			}
			s.TraceID = hex.EncodeToString(x)
		case f == 2 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return s, err
			}
			s.SpanID = hex.EncodeToString(x)
		case f == 4 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return s, err
			}
			s.ParentID = hex.EncodeToString(x)
		case f == 5 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return s, err
			}
			s.Name = clip(string(x))
		case f == 6 && w == wireVarint:
			x, err := r.varint()
			if err != nil {
				return s, err
			}
			s.Kind = int(x)
		case f == 7 && w == wire64:
			if s.StartNano, err = r.fixed64(); err != nil {
				return s, err
			}
		case f == 8 && w == wire64:
			if s.EndNano, err = r.fixed64(); err != nil {
				return s, err
			}
		case f == 9 && w == wireBytes: // attributes
			kb, err := r.bytes()
			if err != nil {
				return s, err
			}
			if n++; n > maxAttrsPerItem {
				continue
			}
			k, v, err := pbKeyValue(kb)
			if err != nil {
				return s, err
			}
			if spanAllow[k] {
				s.set(k, v)
			}
		case f == 11 && w == wireBytes: // events: only "exception" is read
			eb, err := r.bytes()
			if err != nil {
				return s, err
			}
			t, m, st := pbException(eb)
			s.setExc(t, m, st)
		case f == 15 && w == wireBytes: // status
			sb, err := r.bytes()
			if err != nil {
				return s, err
			}
			sr := &pbReader{b: sb}
			for !sr.done() {
				sf, sw, err := sr.next()
				if err != nil {
					return s, err
				}
				if sf == 3 && sw == wireVarint {
					x, err := sr.varint()
					if err != nil {
						return s, err
					}
					s.StatusCode = int(x)
					continue
				}
				if err := sr.skip(sw); err != nil {
					return s, err
				}
			}
		default:
			if err := r.skip(w); err != nil {
				return s, err
			}
		}
	}
	return s, nil
}

// pbException returns exception.type, exception.message and exception.stacktrace when the span event is named
// "exception".
func pbException(b []byte) (typ, msg, stack string) {
	r := &pbReader{b: b}
	name := ""
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return "", "", ""
		}
		switch {
		case f == 2 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return "", "", ""
			}
			name = string(x)
		case f == 3 && w == wireBytes:
			kb, err := r.bytes()
			if err != nil {
				return "", "", ""
			}
			if k, v, err := pbKeyValue(kb); err == nil {
				switch k {
				case "exception.type":
					typ = v.str()
				case "exception.message":
					msg = v.str()
				case "exception.stacktrace":
					stack = v.str()
				}
			}
		default:
			if r.skip(w) != nil {
				return "", "", ""
			}
		}
	}
	if name == "exception" {
		return typ, msg, stack
	}
	return "", "", ""
}

// DecodeTracesPB decodes an ExportTraceServiceRequest.
func DecodeTracesPB(b []byte) ([]Span, error) {
	var out []Span
	top := &pbReader{b: b}
	for !top.done() {
		f, w, err := top.next()
		if err != nil {
			return nil, err
		}
		if f != 1 || w != wireBytes { // resource_spans
			if err := top.skip(w); err != nil {
				return nil, err
			}
			continue
		}
		rsb, err := top.bytes()
		if err != nil {
			return nil, err
		}
		var res Resource
		var scopes [][]byte
		rr := &pbReader{b: rsb}
		for !rr.done() {
			f, w, err := rr.next()
			if err != nil {
				return nil, err
			}
			switch {
			case f == 1 && w == wireBytes:
				x, err := rr.bytes()
				if err != nil {
					return nil, err
				}
				if res, err = pbResource(x); err != nil {
					return nil, err
				}
			case f == 2 && w == wireBytes:
				x, err := rr.bytes()
				if err != nil {
					return nil, err
				}
				scopes = append(scopes, x)
			default:
				if err := rr.skip(w); err != nil {
					return nil, err
				}
			}
		}
		for _, sb := range scopes {
			sr := &pbReader{b: sb}
			for !sr.done() {
				f, w, err := sr.next()
				if err != nil {
					return nil, err
				}
				if f == 2 && w == wireBytes { // spans
					x, err := sr.bytes()
					if err != nil {
						return nil, err
					}
					if len(out) >= maxSpansPerRequest {
						return nil, errTooMany
					}
					sp, err := pbSpan(x, res)
					if err != nil {
						return nil, err
					}
					out = append(out, sp)
					continue
				}
				if err := sr.skip(w); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

func pbLogRecord(b []byte, res Resource) (Log, error) {
	l := Log{Res: res, Attrs: map[string]string{}}
	r := &pbReader{b: b}
	n := 0
	var eventNameField string
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return l, err
		}
		switch {
		case f == 1 && w == wire64:
			if l.TimeNano, err = r.fixed64(); err != nil {
				return l, err
			}
		case f == 9 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return l, err
			}
			l.TraceID = hex.EncodeToString(x)
		case f == 10 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return l, err
			}
			l.SpanID = hex.EncodeToString(x)
		case f == 12 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return l, err
			}
			eventNameField = clip(string(x))
		case f == 6 && w == wireBytes:
			kb, err := r.bytes()
			if err != nil {
				return l, err
			}
			if n++; n > maxAttrsPerItem {
				continue
			}
			k, v, err := pbKeyValue(kb)
			if err != nil {
				return l, err
			}
			if k == "event.name" {
				l.EventName = v.str()
			} else if helperAllow[k] {
				l.Attrs[k] = clip(v.str())
			}
		default: // body, severity and the rest are never read: helper events carry no free text
			if err := r.skip(w); err != nil {
				return l, err
			}
		}
	}
	if l.EventName == "" {
		l.EventName = eventNameField
	}
	return l, nil
}

// DecodeLogsPB decodes an ExportLogsServiceRequest.
func DecodeLogsPB(b []byte) ([]Log, error) {
	var out []Log
	top := &pbReader{b: b}
	for !top.done() {
		f, w, err := top.next()
		if err != nil {
			return nil, err
		}
		if f != 1 || w != wireBytes { // resource_logs
			if err := top.skip(w); err != nil {
				return nil, err
			}
			continue
		}
		rlb, err := top.bytes()
		if err != nil {
			return nil, err
		}
		var res Resource
		var scopes [][]byte
		rr := &pbReader{b: rlb}
		for !rr.done() {
			f, w, err := rr.next()
			if err != nil {
				return nil, err
			}
			switch {
			case f == 1 && w == wireBytes:
				x, err := rr.bytes()
				if err != nil {
					return nil, err
				}
				if res, err = pbResource(x); err != nil {
					return nil, err
				}
			case f == 2 && w == wireBytes:
				x, err := rr.bytes()
				if err != nil {
					return nil, err
				}
				scopes = append(scopes, x)
			default:
				if err := rr.skip(w); err != nil {
					return nil, err
				}
			}
		}
		for _, sb := range scopes {
			sr := &pbReader{b: sb}
			for !sr.done() {
				f, w, err := sr.next()
				if err != nil {
					return nil, err
				}
				if f == 2 && w == wireBytes { // log_records
					x, err := sr.bytes()
					if err != nil {
						return nil, err
					}
					if len(out) >= maxLogsPerRequest {
						return nil, errTooMany
					}
					lg, err := pbLogRecord(x, res)
					if err != nil {
						return nil, err
					}
					out = append(out, lg)
					continue
				}
				if err := sr.skip(w); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

// ── JSON (OTLP/HTTP with Content-Type: application/json) ───────────────────

type jsonAny struct {
	StringValue *string         `json:"stringValue"`
	IntValue    json.RawMessage `json:"intValue"`
	DoubleValue *float64        `json:"doubleValue"`
	BoolValue   *bool           `json:"boolValue"`
}

type jsonKV struct {
	Key   string  `json:"key"`
	Value jsonAny `json:"value"`
}

func (a jsonAny) value() attrValue {
	switch {
	case a.StringValue != nil:
		return attrValue{s: clip(*a.StringValue)}
	case len(a.IntValue) > 0:
		t := string(a.IntValue)
		if len(t) > 1 && t[0] == '"' {
			t = t[1 : len(t)-1]
		}
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return attrValue{i: n, isInt: true}
		}
	case a.DoubleValue != nil:
		return attrValue{s: strconv.FormatFloat(*a.DoubleValue, 'g', -1, 64)}
	case a.BoolValue != nil:
		return attrValue{s: strconv.FormatBool(*a.BoolValue)}
	}
	return attrValue{}
}

type jsonResource struct {
	Attributes []jsonKV `json:"attributes"`
}

func (jr jsonResource) resource() Resource {
	var res Resource
	for i, kv := range jr.Attributes {
		if i >= maxAttrsPerItem {
			break
		}
		if resourceAllow[kv.Key] {
			res.set(kv.Key, kv.Value.value())
		}
	}
	return res
}

// jsonNano reads a uint64 that OTLP/JSON may encode as a string or a number.
func jsonNano(raw json.RawMessage) uint64 {
	t := string(raw)
	if len(t) > 1 && t[0] == '"' {
		t = t[1 : len(t)-1]
	}
	n, _ := strconv.ParseUint(t, 10, 64)
	return n
}

type jsonSpan struct {
	TraceID    string          `json:"traceId"`
	SpanID     string          `json:"spanId"`
	ParentID   string          `json:"parentSpanId"`
	Name       string          `json:"name"`
	Kind       int             `json:"kind"`
	Start      json.RawMessage `json:"startTimeUnixNano"`
	End        json.RawMessage `json:"endTimeUnixNano"`
	Attributes []jsonKV        `json:"attributes"`
	Events     []struct {
		Name       string   `json:"name"`
		Attributes []jsonKV `json:"attributes"`
	} `json:"events"`
	Status struct {
		Code int `json:"code"`
	} `json:"status"`
}

// DecodeTracesJSON decodes an ExportTraceServiceRequest in OTLP/JSON form.
func DecodeTracesJSON(b []byte) ([]Span, error) {
	var req struct {
		ResourceSpans []struct {
			Resource   jsonResource `json:"resource"`
			ScopeSpans []struct {
				Spans []jsonSpan `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, err
	}
	var out []Span
	for _, rs := range req.ResourceSpans {
		res := rs.Resource.resource()
		for _, ss := range rs.ScopeSpans {
			for _, js := range ss.Spans {
				if len(out) >= maxSpansPerRequest {
					return nil, errTooMany
				}
				s := Span{Res: res, TraceID: lowerHex(js.TraceID), SpanID: lowerHex(js.SpanID), ParentID: lowerHex(js.ParentID),
					Name: clip(js.Name), Kind: js.Kind, StartNano: jsonNano(js.Start), EndNano: jsonNano(js.End), StatusCode: js.Status.Code}
				for i, kv := range js.Attributes {
					if i >= maxAttrsPerItem {
						break
					}
					if spanAllow[kv.Key] {
						s.set(kv.Key, kv.Value.value())
					}
				}
				for _, ev := range js.Events {
					if ev.Name != "exception" {
						continue
					}
					var t, m, st string
					for _, kv := range ev.Attributes {
						switch kv.Key {
						case "exception.type":
							t = kv.Value.value().str()
						case "exception.message":
							m = kv.Value.value().str()
						case "exception.stacktrace":
							st = kv.Value.value().str()
						}
					}
					s.setExc(t, m, st)
				}
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// DecodeLogsJSON decodes an ExportLogsServiceRequest in OTLP/JSON form.
func DecodeLogsJSON(b []byte) ([]Log, error) {
	var req struct {
		ResourceLogs []struct {
			Resource  jsonResource `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					Time       json.RawMessage `json:"timeUnixNano"`
					TraceID    string          `json:"traceId"`
					SpanID     string          `json:"spanId"`
					EventName  string          `json:"eventName"`
					Attributes []jsonKV        `json:"attributes"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, err
	}
	var out []Log
	for _, rl := range req.ResourceLogs {
		res := rl.Resource.resource()
		for _, sl := range rl.ScopeLogs {
			for _, jl := range sl.LogRecords {
				if len(out) >= maxLogsPerRequest {
					return nil, errTooMany
				}
				l := Log{Res: res, TimeNano: jsonNano(jl.Time), TraceID: lowerHex(jl.TraceID), SpanID: lowerHex(jl.SpanID),
					EventName: clip(jl.EventName), Attrs: map[string]string{}}
				for i, kv := range jl.Attributes {
					if i >= maxAttrsPerItem {
						break
					}
					if kv.Key == "event.name" {
						l.EventName = kv.Value.value().str()
					} else if helperAllow[kv.Key] {
						l.Attrs[kv.Key] = clip(kv.Value.value().str())
					}
				}
				out = append(out, l)
			}
		}
	}
	return out, nil
}

func lowerHex(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'F' {
			b[i] = c + 32
		}
	}
	return string(b)
}
