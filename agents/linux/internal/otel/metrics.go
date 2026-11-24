package otel

// metrics.go - OTLP metrics (APM spec item 3). Only runtime and pool metrics on an allowlist are kept; everything
// else is dropped and counted. Attributes are limited to a short allowlist of enumerations (a state, a pool or
// space name), never free-form values. Per instance and per flush the agent keeps last, min, max, sum and count for
// each series, at most 100 series per instance. Exponential histograms are rejected with a counted reason.

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxMetricPointsPerRequest = 20000
	maxMetricSeriesPerInst    = 100
	maxMetricNameLen          = 96
)

// metricNamePrefixes are the metric names (by prefix) that are kept.
var metricNamePrefixes = []string{
	"process.cpu.", "process.memory.", "process.runtime.", "process.uptime", "v8js.", "nodejs.", "jvm.", "dotnet.",
	"db.client.connections.", "db.client.connection.", "http.server.active_requests",
}

// metricAttrAllow are the only metric attributes kept: enumerations, not identifiers.
var metricAttrAllow = map[string]bool{
	"state": true, "type": true, "pool.name": true, "gc": true,
	"db.client.connection.state": true, "db.client.connection.pool.name": true,
	"v8js.heap.space.name": true, "jvm.memory.pool.name": true, "jvm.memory.type": true, "jvm.gc.name": true,
	"dotnet.gc.heap.generation": true,
}

func metricNameAllowed(n string) bool {
	if n == "" || len(n) > maxMetricNameLen {
		return false
	}
	for _, p := range metricNamePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// MetricPoint is one decoded data point.
type MetricPoint struct {
	Res      Resource
	Name     string
	Unit     string
	Attr     string // "k=v,k=v" over the allowlisted attributes, sorted by key
	Value    float64
	TimeNano uint64
}

// MetricsDecoded is what a request yielded, with counts of what was dropped.
type MetricsDecoded struct {
	Points   []MetricPoint
	Dropped  int64 // not on the allowlist
	Rejected int64 // exponential histograms and summaries
}

func joinAttrs(kv map[string]string) string {
	if len(kv) == 0 {
		return ""
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+clipN(kv[k], 64))
	}
	return strings.Join(parts, ",")
}

func goodValue(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// ── protobuf ───────────────────────────────────────────────────────────────

// DecodeMetricsPB decodes an ExportMetricsServiceRequest.
func DecodeMetricsPB(b []byte) (*MetricsDecoded, error) {
	out := &MetricsDecoded{}
	top := &pbReader{b: b}
	for !top.done() {
		f, w, err := top.next()
		if err != nil {
			return nil, err
		}
		if f != 1 || w != wireBytes {
			if err := top.skip(w); err != nil {
				return nil, err
			}
			continue
		}
		rb, err := top.bytes()
		if err != nil {
			return nil, err
		}
		if err := pbResourceMetrics(rb, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func pbResourceMetrics(b []byte, out *MetricsDecoded) error {
	r := &pbReader{b: b}
	var res Resource
	var scopes [][]byte
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case f == 1 && w == wireBytes:
			rb, err := r.bytes()
			if err != nil {
				return err
			}
			if res, err = pbResource(rb); err != nil {
				return err
			}
		case f == 2 && w == wireBytes:
			sb, err := r.bytes()
			if err != nil {
				return err
			}
			scopes = append(scopes, sb)
		default:
			if err := r.skip(w); err != nil {
				return err
			}
		}
	}
	for _, sb := range scopes {
		sr := &pbReader{b: sb}
		for !sr.done() {
			f, w, err := sr.next()
			if err != nil {
				return err
			}
			if f == 2 && w == wireBytes {
				mb, err := sr.bytes()
				if err != nil {
					return err
				}
				if err := pbMetric(mb, res, out); err != nil {
					return err
				}
				if len(out.Points) > maxMetricPointsPerRequest {
					return errTooMany
				}
				continue
			}
			if err := sr.skip(w); err != nil {
				return err
			}
		}
	}
	return nil
}

func pbMetric(b []byte, res Resource, out *MetricsDecoded) error {
	r := &pbReader{b: b}
	var name, unit string
	var kind int // 5 gauge, 7 sum, 9 histogram, 10 exp histogram, 11 summary
	var body []byte
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return err
		}
		switch {
		case f == 1 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return err
			}
			name = string(x)
		case f == 3 && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return err
			}
			unit = clipN(string(x), 16)
		case (f == 5 || f == 7 || f == 9 || f == 10 || f == 11) && w == wireBytes:
			x, err := r.bytes()
			if err != nil {
				return err
			}
			kind, body = f, x
		default:
			if err := r.skip(w); err != nil {
				return err
			}
		}
	}
	if !metricNameAllowed(name) {
		out.Dropped++
		return nil
	}
	if kind == 10 || kind == 11 {
		out.Rejected++
		return nil
	}
	if kind == 0 {
		return nil
	}
	dr := &pbReader{b: body}
	for !dr.done() {
		f, w, err := dr.next()
		if err != nil {
			return err
		}
		if f == 1 && w == wireBytes {
			pb, err := dr.bytes()
			if err != nil {
				return err
			}
			p, ok, err := pbDataPoint(pb, kind == 9)
			if err != nil {
				return err
			}
			if ok {
				out.Points = append(out.Points, MetricPoint{Res: res, Name: name, Unit: unit, Attr: p.Attr, Value: p.Value, TimeNano: p.TimeNano})
			}
			continue
		}
		if err := dr.skip(w); err != nil {
			return err
		}
	}
	return nil
}

type pbPoint struct {
	Attr     string
	Value    float64
	TimeNano uint64
}

// pbDataPoint decodes a NumberDataPoint, or a HistogramDataPoint (reduced to its mean).
func pbDataPoint(b []byte, hist bool) (pbPoint, bool, error) {
	r := &pbReader{b: b}
	var p pbPoint
	attrs := map[string]string{}
	var have bool
	var count uint64
	var sum float64
	attrField := 7
	if hist {
		attrField = 9
	}
	n := 0
	for !r.done() {
		f, w, err := r.next()
		if err != nil {
			return p, false, err
		}
		switch {
		case f == attrField && w == wireBytes:
			kb, err := r.bytes()
			if err != nil {
				return p, false, err
			}
			if n++; n > maxAttrsPerItem {
				continue
			}
			if k, v, err := pbKeyValue(kb); err == nil && metricAttrAllow[k] {
				attrs[k] = v.str()
			}
		case f == 3 && w == wire64:
			x, err := r.fixed64()
			if err != nil {
				return p, false, err
			}
			p.TimeNano = x
		case !hist && f == 4 && w == wire64:
			x, err := r.fixed64()
			if err != nil {
				return p, false, err
			}
			p.Value, have = math.Float64frombits(x), true
		case !hist && f == 6 && w == wire64:
			x, err := r.fixed64()
			if err != nil {
				return p, false, err
			}
			p.Value, have = float64(int64(x)), true
		case hist && f == 4 && w == wire64:
			x, err := r.fixed64()
			if err != nil {
				return p, false, err
			}
			count = x
		case hist && f == 5 && w == wire64:
			x, err := r.fixed64()
			if err != nil {
				return p, false, err
			}
			sum = math.Float64frombits(x)
		default:
			if err := r.skip(w); err != nil {
				return p, false, err
			}
		}
	}
	if hist {
		if count == 0 {
			return p, false, nil
		}
		p.Value, have = sum/float64(count), true
	}
	if !have || !goodValue(p.Value) {
		return p, false, nil
	}
	p.Attr = joinAttrs(attrs)
	return p, true, nil
}

// ── JSON ───────────────────────────────────────────────────────────────────

type jsonNumPoint struct {
	Attributes []jsonKV        `json:"attributes"`
	Time       json.RawMessage `json:"timeUnixNano"`
	AsDouble   *float64        `json:"asDouble"`
	AsInt      json.RawMessage `json:"asInt"`
	Count      json.RawMessage `json:"count"`
	Sum        *float64        `json:"sum"`
}

type jsonMetricData struct {
	DataPoints []jsonNumPoint `json:"dataPoints"`
}

// DecodeMetricsJSON decodes an ExportMetricsServiceRequest in OTLP/JSON form.
func DecodeMetricsJSON(b []byte) (*MetricsDecoded, error) {
	var req struct {
		ResourceMetrics []struct {
			Resource     jsonResource `json:"resource"`
			ScopeMetrics []struct {
				Metrics []struct {
					Name                 string          `json:"name"`
					Unit                 string          `json:"unit"`
					Gauge                *jsonMetricData `json:"gauge"`
					Sum                  *jsonMetricData `json:"sum"`
					Histogram            *jsonMetricData `json:"histogram"`
					ExponentialHistogram json.RawMessage `json:"exponentialHistogram"`
					Summary              json.RawMessage `json:"summary"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, err
	}
	out := &MetricsDecoded{}
	for _, rm := range req.ResourceMetrics {
		res := rm.Resource.resource()
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if !metricNameAllowed(m.Name) {
					out.Dropped++
					continue
				}
				if len(m.ExponentialHistogram) > 0 || len(m.Summary) > 0 {
					out.Rejected++
					continue
				}
				var data *jsonMetricData
				hist := false
				switch {
				case m.Gauge != nil:
					data = m.Gauge
				case m.Sum != nil:
					data = m.Sum
				case m.Histogram != nil:
					data, hist = m.Histogram, true
				default:
					continue
				}
				for _, dp := range data.DataPoints {
					if len(out.Points) >= maxMetricPointsPerRequest {
						return nil, errTooMany
					}
					var v float64
					ok := false
					if hist {
						c, _ := strconv.ParseFloat(strings.Trim(string(dp.Count), `"`), 64)
						if dp.Sum != nil && c > 0 {
							v, ok = *dp.Sum/c, true
						}
					} else if dp.AsDouble != nil {
						v, ok = *dp.AsDouble, true
					} else if len(dp.AsInt) > 0 {
						if n, err := strconv.ParseInt(strings.Trim(string(dp.AsInt), `"`), 10, 64); err == nil {
							v, ok = float64(n), true
						}
					}
					if !ok || !goodValue(v) {
						continue
					}
					attrs := map[string]string{}
					for i, kv := range dp.Attributes {
						if i >= maxAttrsPerItem {
							break
						}
						if metricAttrAllow[kv.Key] {
							attrs[kv.Key] = kv.Value.value().str()
						}
					}
					out.Points = append(out.Points, MetricPoint{Res: res, Name: m.Name, Unit: clipN(m.Unit, 16), Attr: joinAttrs(attrs), Value: v, TimeNano: jsonNano(dp.Time)})
				}
			}
		}
	}
	return out, nil
}

// ── aggregation ────────────────────────────────────────────────────────────

type metricKey struct {
	svc      svcKey
	instance string
	name     string
	attr     string
}

type metricVal struct {
	unit           string
	identity       string
	last, min, max float64
	sum            float64
	count          int64
	lastNano       uint64
}

// BatchMetric is one series for one instance since the last flush.
type BatchMetric struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Instance    string    `json:"instance"` // service.instance.id, or "pid:<n>" when the app did not set one
	Name        string    `json:"name"`
	Attr        string    `json:"attr,omitempty"`
	Unit        string    `json:"unit,omitempty"`
	Identity    string    `json:"identity"`
	Minute      time.Time `json:"minute"`
	Last        float64   `json:"last"`
	Min         float64   `json:"min"`
	Max         float64   `json:"max"`
	Sum         float64   `json:"sum"`
	Count       int64     `json:"count"`
}

// IngestMetrics aggregates decoded points. identity is the sender's binding result for the service.
func (a *Aggregator) IngestMetrics(p MetricPoint, peer Peer, identity string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mt == nil {
		a.mt = map[metricKey]*metricVal{}
		a.mtN = map[string]int{}
	}
	svc := svcKey{p.Res.Service, envOf(p.Res.Environment)}
	if svc.name == "" {
		a.Stats.NoService++
		return
	}
	inst := p.Res.InstanceRef
	if inst == "" && peer.PID > 0 {
		inst = "pid:" + strconv.Itoa(peer.PID)
	}
	if inst == "" {
		inst = "unknown"
	}
	inst = clipN(inst, 128)
	k := metricKey{svc, inst, p.Name, p.Attr}
	v := a.mt[k]
	if v == nil {
		ik := svc.name + "|" + svc.env + "|" + inst
		if a.mtN[ik] >= maxMetricSeriesPerInst {
			a.Stats.MetricDrops++
			return
		}
		a.mtN[ik]++
		v = &metricVal{unit: p.Unit, identity: identity, min: p.Value, max: p.Value}
		a.mt[k] = v
	}
	if p.TimeNano >= v.lastNano {
		v.last, v.lastNano = p.Value, p.TimeNano
	}
	if p.Value < v.min {
		v.min = p.Value
	}
	if p.Value > v.max {
		v.max = p.Value
	}
	v.sum += p.Value
	v.count++
	if identity == IdentityAsserted {
		v.identity = IdentityAsserted
	}
	a.Stats.MetricPoints++
}

func (a *Aggregator) drainMetrics(b *Batch, now time.Time) {
	minute := now.UTC().Truncate(time.Minute)
	for k, v := range a.mt {
		b.Metrics = append(b.Metrics, BatchMetric{Service: k.svc.name, Environment: k.svc.env, Instance: k.instance, Name: k.name, Attr: k.attr,
			Unit: v.unit, Identity: v.identity, Minute: minute, Last: v.last, Min: v.min, Max: v.max, Sum: v.sum, Count: v.count})
	}
	a.mt, a.mtN = nil, nil
}
