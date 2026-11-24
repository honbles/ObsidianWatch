package otel

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func pbGaugePoint(attrs []func(*pbw), v float64, tn uint64) func(*pbw) {
	return func(dp *pbw) {
		for _, a := range attrs {
			dp.msg(7, a)
		}
		dp.fix64(3, tn)
		dp.fix64(4, math.Float64bits(v))
	}
}

func pbMetricsReq(res []func(*pbw), metrics ...func(*pbw)) []byte {
	w := &pbw{}
	w.msg(1, func(rm *pbw) {
		rm.msg(1, func(r *pbw) {
			for _, a := range res {
				r.msg(1, a)
			}
		})
		rm.msg(2, func(sm *pbw) {
			for _, m := range metrics {
				sm.msg(2, m)
			}
		})
	})
	return w.b
}

func pbGauge(name, unit string, pts ...func(*pbw)) func(*pbw) {
	return func(m *pbw) {
		m.str(1, name)
		m.str(3, unit)
		m.msg(5, func(g *pbw) {
			for _, p := range pts {
				g.msg(1, p)
			}
		})
	}
}

func TestMetricsPBAllowlistAndAttrs(t *testing.T) {
	req := pbMetricsReq(stdRes("api", "prod", pbStrAttr("service.instance.id", "i-1")),
		pbGauge("process.cpu.utilization", "1", pbGaugePoint([]func(*pbw){pbStrAttr("state", "user"), pbStrAttr("user.email", "a@b.c")}, 0.42, 5)),
		pbGauge("http.client.duration", "ms", pbGaugePoint(nil, 1, 5)),
		pbGauge("secret.thing", "", pbGaugePoint(nil, 1, 5)))
	d, err := DecodeMetricsPB(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Points) != 1 || d.Dropped != 2 {
		t.Fatalf("points=%d dropped=%d", len(d.Points), d.Dropped)
	}
	p := d.Points[0]
	if p.Name != "process.cpu.utilization" || p.Attr != "state=user" || p.Value != 0.42 || p.Res.InstanceRef != "i-1" {
		t.Fatalf("%+v", p)
	}
}

func TestMetricsExpHistogramRejected(t *testing.T) {
	req := pbMetricsReq(stdRes("api", "prod"), func(m *pbw) {
		m.str(1, "nodejs.eventloop.delay")
		m.msg(10, func(*pbw) {})
	})
	d, err := DecodeMetricsPB(req)
	if err != nil || len(d.Points) != 0 || d.Rejected != 1 {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestMetricsJSON(t *testing.T) {
	js := `{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}},{"key":"deployment.environment","value":{"stringValue":"prod"}}]},
	"scopeMetrics":[{"metrics":[
	 {"name":"jvm.memory.used","unit":"By","gauge":{"dataPoints":[{"asInt":"1048576","timeUnixNano":"5","attributes":[{"key":"jvm.memory.pool.name","value":{"stringValue":"G1 Old Gen"}},{"key":"url","value":{"stringValue":"/x"}}]}]}},
	 {"name":"nodejs.eventloop.delay","histogram":{"dataPoints":[{"count":"4","sum":8,"timeUnixNano":"6"}]}},
	 {"name":"foo.bar","gauge":{"dataPoints":[{"asDouble":1}]}},
	 {"name":"jvm.gc.duration","exponentialHistogram":{}}]}]}]}`
	d, err := DecodeMetricsJSON([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Points) != 2 || d.Dropped != 1 || d.Rejected != 1 {
		t.Fatalf("%+v", d)
	}
	if d.Points[0].Value != 1048576 || d.Points[0].Attr != "jvm.memory.pool.name=G1 Old Gen" || d.Points[1].Value != 2 {
		t.Fatalf("%+v", d.Points)
	}
}

func TestMetricsAggregationAndCaps(t *testing.T) {
	a, now := newTestAgg(AggOptions{})
	res := Resource{Service: "api", Environment: "prod", InstanceRef: "i-1"}
	for i, v := range []float64{5, 9, 1} {
		a.IngestMetrics(MetricPoint{Res: res, Name: "process.cpu.utilization", Value: v, TimeNano: uint64(i + 1)}, verifiedPeer, IdentityAsserted)
	}
	// a late out-of-order point does not replace "last"
	a.IngestMetrics(MetricPoint{Res: res, Name: "process.cpu.utilization", Value: 100, TimeNano: 0}, verifiedPeer, IdentityAsserted)
	for i := 0; i < 150; i++ {
		a.IngestMetrics(MetricPoint{Res: res, Name: "jvm.x", Attr: fmt.Sprintf("state=s%d", i), Value: 1, TimeNano: 1}, verifiedPeer, IdentityAsserted)
	}
	// no instance id: falls back to the verified pid
	a.IngestMetrics(MetricPoint{Res: Resource{Service: "api", Environment: "prod"}, Name: "process.uptime", Value: 3, TimeNano: 1}, verifiedPeer, IdentityAsserted)
	*now = now.Add(2 * time.Minute)
	b := a.Flush("ag", false)
	var cpu *BatchMetric
	n := 0
	pid := false
	for i := range b.Metrics {
		m := &b.Metrics[i]
		if m.Name == "process.cpu.utilization" {
			cpu = m
		}
		if m.Instance == "pid:100" {
			pid = true
		}
		if m.Instance == "i-1" {
			n++
		}
	}
	if cpu == nil || cpu.Last != 1 || cpu.Min != 1 || cpu.Max != 100 || cpu.Count != 4 || cpu.Sum != 115 {
		t.Fatalf("%+v", cpu)
	}
	if n != maxMetricSeriesPerInst || !pid || a.Stats.MetricDrops != 51 {
		t.Fatalf("series=%d pid=%v drops=%d", n, pid, a.Stats.MetricDrops)
	}
	if b.Empty() {
		t.Fatal("a batch with metrics is not empty")
	}
}
