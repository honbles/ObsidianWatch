package otel

// sampling.go - per-service trace sampling controls (APM spec item 13). The defaults reproduce the built-in
// behaviour: every error, every slow trace and every security-flagged trace is kept, plus a small share of ordinary
// traces. An admin can change the baseline share, cap errors per minute and cap what one flush keeps. Counters per
// reason (seen and kept) are sent so loss is visible. Under a flush budget the order of dropping is baseline, then
// slow, then error; security is never dropped.

import "time"

// SamplePolicy is a service's sampling settings. Zero values mean the default.
type SamplePolicy struct {
	BaselinePct    *float64 `json:"baseline_pct,omitempty"`      // nil = the agent default; 0 = no baseline traces
	ErrorMaxPerMin int      `json:"error_max_per_min,omitempty"` // 0 = keep every error trace
	MaxPerFlush    int      `json:"max_per_flush,omitempty"`     // 0 = the default
}

const defaultMaxKeptPerFlush = 500

var sampleRank = map[string]int{"baseline": 0, "slow": 1, "error": 2, "security": 3}

type sampKey struct {
	svc    svcKey
	reason string
}

// BatchSampling is how many traces of one kind a service completed and how many were kept since the last flush.
type BatchSampling struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Reason      string `json:"reason"`
	Seen        int64  `json:"seen"`
	Kept        int64  `json:"kept"`
}

func (a *Aggregator) samplePolicy(svc svcKey) SamplePolicy {
	if a.opt.SamplingFn != nil {
		return a.opt.SamplingFn(svc.name, svc.env)
	}
	return SamplePolicy{}
}

func (a *Aggregator) sampSeen(svc svcKey, reason string) {
	if a.samp == nil {
		a.samp = map[sampKey]*[2]int64{}
	}
	k := sampKey{svc, reason}
	if a.samp[k] == nil {
		a.samp[k] = &[2]int64{}
	}
	a.samp[k][0]++
}

func (a *Aggregator) sampKept(svc svcKey, reason string, d int64) {
	if a.samp == nil {
		a.samp = map[sampKey]*[2]int64{}
	}
	k := sampKey{svc, reason}
	if a.samp[k] == nil {
		a.samp[k] = &[2]int64{}
	}
	a.samp[k][1] += d
}

// sampleAdmit applies the per-minute error cap and the flush budget to a trace that qualified for a reason.
// It returns false when the trace is dropped. A lower-ranked kept trace is evicted to make room for a higher one.
func (a *Aggregator) sampleAdmit(svc svcKey, reason string, pol SamplePolicy, now time.Time) bool {
	if reason == "error" && pol.ErrorMaxPerMin > 0 {
		m := now.Unix() / 60
		if a.errMin == nil || a.errMinAt != m {
			a.errMin, a.errMinAt = map[svcKey]int{}, m
		}
		if a.errMin[svc] >= pol.ErrorMaxPerMin {
			return false
		}
		a.errMin[svc]++
	}
	max := pol.MaxPerFlush
	if max <= 0 {
		max = defaultMaxKeptPerFlush
	}
	if len(a.kept) < max {
		return true
	}
	if reason == "security" { // never dropped: it may exceed the budget
		return true
	}
	victim, vr := -1, sampleRank[reason]
	for i, t := range a.kept {
		if r := sampleRank[t.KeepReason]; r < vr {
			victim, vr = i, r
			if r == 0 {
				break
			}
		}
	}
	if victim < 0 {
		return false
	}
	ev := a.kept[victim]
	a.kept = append(a.kept[:victim], a.kept[victim+1:]...)
	a.sampKept(svcKey{ev.Service, ev.Environment}, ev.KeepReason, -1)
	a.Stats.TracesKept--
	return true
}

func (a *Aggregator) drainSampling(b *Batch) {
	for k, v := range a.samp {
		if v[0] == 0 && v[1] == 0 {
			continue
		}
		b.Sampling = append(b.Sampling, BatchSampling{Service: k.svc.name, Environment: k.svc.env, Reason: k.reason, Seen: v[0], Kept: v[1]})
	}
	a.samp = nil
}

// cleanSamplePolicy bounds what the server sends: a share between 0 and 100, a sane error cap and flush budget.
func cleanSamplePolicy(p *SamplePolicy) *SamplePolicy {
	c := SamplePolicy{ErrorMaxPerMin: p.ErrorMaxPerMin, MaxPerFlush: p.MaxPerFlush}
	if p.BaselinePct != nil {
		v := *p.BaselinePct
		if v < 0 {
			v = 0
		}
		if v > 100 {
			v = 100
		}
		c.BaselinePct = &v
	}
	if c.ErrorMaxPerMin < 0 {
		c.ErrorMaxPerMin = 0
	}
	if c.ErrorMaxPerMin > 100000 {
		c.ErrorMaxPerMin = 100000
	}
	if c.MaxPerFlush < 0 {
		c.MaxPerFlush = 0
	}
	if c.MaxPerFlush > 5000 {
		c.MaxPerFlush = 5000
	}
	return &c
}
