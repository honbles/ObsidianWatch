package otel

import (
	"encoding/binary"
	"math"
)

// A tiny protobuf encoder for building OTLP fixtures.
type pbw struct{ b []byte }

func (w *pbw) varint(v uint64) {
	var t [10]byte
	n := binary.PutUvarint(t[:], v)
	w.b = append(w.b, t[:n]...)
}
func (w *pbw) key(f, wire int) { w.varint(uint64(f<<3 | wire)) }
func (w *pbw) bytesF(f int, v []byte) {
	w.key(f, wireBytes)
	w.varint(uint64(len(v)))
	w.b = append(w.b, v...)
}
func (w *pbw) str(f int, s string)  { w.bytesF(f, []byte(s)) }
func (w *pbw) vint(f int, v uint64) { w.key(f, wireVarint); w.varint(v) }
func (w *pbw) fix64(f int, v uint64) {
	w.key(f, wire64)
	var t [8]byte
	binary.LittleEndian.PutUint64(t[:], v)
	w.b = append(w.b, t[:]...)
}
func (w *pbw) msg(f int, fn func(*pbw)) {
	n := &pbw{}
	fn(n)
	w.bytesF(f, n.b)
}

func pbStrAttr(k, v string) func(*pbw) {
	return func(w *pbw) {
		w.str(1, k)
		w.msg(2, func(a *pbw) { a.str(1, v) })
	}
}
func pbIntAttr(k string, v int64) func(*pbw) {
	return func(w *pbw) {
		w.str(1, k)
		w.msg(2, func(a *pbw) { a.vint(3, uint64(v)) })
	}
}
func pbDblAttr(k string, v float64) func(*pbw) {
	return func(w *pbw) {
		w.str(1, k)
		w.msg(2, func(a *pbw) { a.fix64(4, math.Float64bits(v)) })
	}
}

type fixSpan struct {
	trace, span, parent string // hex-free raw bytes are fine for tests
	name                string
	kind                int
	start, end          uint64
	status              int
	attrs               []func(*pbw)
	excType             string
}

func (s fixSpan) encode(w *pbw) {
	w.bytesF(1, []byte(s.trace))
	w.bytesF(2, []byte(s.span))
	if s.parent != "" {
		w.bytesF(4, []byte(s.parent))
	}
	w.str(5, s.name)
	w.vint(6, uint64(s.kind))
	w.fix64(7, s.start)
	w.fix64(8, s.end)
	for _, a := range s.attrs {
		w.msg(9, a)
	}
	if s.excType != "" {
		w.msg(11, func(e *pbw) {
			e.fix64(1, s.end)
			e.str(2, "exception")
			e.msg(3, pbStrAttr("exception.type", s.excType))
		})
	}
	if s.status != 0 {
		w.msg(15, func(st *pbw) { st.vint(3, uint64(s.status)) })
	}
}

// traceReq builds an ExportTraceServiceRequest with one resource.
func traceReq(res []func(*pbw), spans ...fixSpan) []byte {
	w := &pbw{}
	w.msg(1, func(rs *pbw) {
		rs.msg(1, func(r *pbw) {
			for _, a := range res {
				r.msg(1, a)
			}
		})
		rs.msg(2, func(ss *pbw) {
			for _, s := range spans {
				s := s
				ss.msg(2, s.encode)
			}
		})
	})
	return w.b
}

func stdRes(service, env string, extra ...func(*pbw)) []func(*pbw) {
	r := []func(*pbw){pbStrAttr("service.name", service), pbStrAttr("deployment.environment", env),
		pbStrAttr("service.instance.id", "inst-1"), pbStrAttr("service.version", "1.4.0"),
		pbStrAttr("telemetry.sdk.language", "java")}
	return append(r, extra...)
}

// logReq builds an ExportLogsServiceRequest with one record.
func logReq(res []func(*pbw), eventName string, trace string, attrs ...func(*pbw)) []byte {
	w := &pbw{}
	w.msg(1, func(rl *pbw) {
		rl.msg(1, func(r *pbw) {
			for _, a := range res {
				r.msg(1, a)
			}
		})
		rl.msg(2, func(sl *pbw) {
			sl.msg(2, func(lr *pbw) {
				lr.fix64(1, 1_700_000_000_000_000_000)
				if trace != "" {
					lr.bytesF(9, []byte(trace))
				}
				lr.msg(6, pbStrAttr("event.name", eventName))
				for _, a := range attrs {
					lr.msg(6, a)
				}
			})
		})
	})
	return w.b
}
