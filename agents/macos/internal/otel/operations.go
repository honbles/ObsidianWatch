package otel

// operations.go - non-HTTP work (APM spec item 7). A consumer span (a message handler) or a root span carrying the
// helper's job name counts as an operation: runs, failures, a latency sketch and the time of the last run, grouped
// by service, kind and a name template. Only names are read: the messaging system, the destination (queue or topic)
// name, the operation and the helper's job name. No message content or identifiers leave the host.

import (
	"strings"
	"time"
)

const (
	maxOpsPerService = 100
	otherOp          = "other"
)

type opKey struct {
	minute time.Time
	svc    svcKey
	kind   string // job | consumer
	name   string
}

type opVal struct {
	runs, failures int64
	hist           [histLen]int64
	sk             *Sketch
	last           time.Time
}

// BatchOperation is one operation's runs in one minute.
type BatchOperation struct {
	Service     string      `json:"service"`
	Environment string      `json:"environment"`
	Kind        string      `json:"kind"`
	Name        string      `json:"name"`
	Minute      time.Time   `json:"minute"`
	Runs        int64       `json:"runs"`
	Failures    int64       `json:"failures"`
	DurBuckets  []int64     `json:"duration_buckets"`
	Sketch      *SketchWire `json:"sketch,omitempty"`
	LastRun     time.Time   `json:"last_run"`
}

// operationOf classifies a span. ok is false for spans that are not operations.
func operationOf(s Span) (kind, name string, ok bool) {
	root := s.ParentID == "" || strings.Trim(s.ParentID, "0") == ""
	switch {
	case s.JobName != "" && (root || s.Kind == kindConsumer):
		kind, name = "job", s.JobName
	case s.Kind == kindConsumer:
		kind = "consumer"
		parts := []string{}
		for _, p := range []string{s.Messaging, s.MessagingDest, s.MessagingOp} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		name = strings.Join(parts, " ")
		if name == "" {
			name = s.Name
		}
		if name == "" && s.CodeFunc != "" {
			name = s.CodeFunc
		}
	default:
		return "", "", false
	}
	name = clipN(templateName(strings.TrimSpace(name)), 96)
	if name == "" {
		return "", "", false
	}
	return kind, name, true
}

func (a *Aggregator) addOperation(svc svcKey, s Span, now time.Time) {
	kind, name, ok := operationOf(s)
	if !ok {
		return
	}
	if a.opSeen == nil {
		a.opSeen = map[svcKey]map[[2]string]bool{}
	}
	seen := a.opSeen[svc]
	if seen == nil {
		seen = map[[2]string]bool{}
		a.opSeen[svc] = seen
	}
	k2 := [2]string{kind, name}
	if !seen[k2] {
		if len(seen) >= maxOpsPerService {
			name = otherOp
			k2 = [2]string{kind, name}
		}
		seen[k2] = true
	}
	end := time.Unix(0, int64(s.EndNano))
	if s.EndNano == 0 || end.After(now.Add(maxSkew)) || end.Before(now.Add(-maxSkew)) {
		end = now
	}
	key := opKey{minute: end.UTC().Truncate(time.Minute), svc: svc, kind: kind, name: name}
	if a.ops == nil {
		a.ops = map[opKey]*opVal{}
	}
	v := a.ops[key]
	if v == nil {
		if len(a.ops) >= a.opt.MaxStatKeys {
			a.Stats.StatDrops++
			return
		}
		v = &opVal{}
		a.ops[key] = v
	}
	v.runs++
	v.hist[durBucket(s.DurationMs())]++
	if v.sk == nil {
		v.sk = NewSketch()
	}
	v.sk.Add(s.DurationMs())
	if s.IsError() {
		v.failures++
	}
	if end.After(v.last) {
		v.last = end
	}
	a.Stats.OperationRuns++
}

func (a *Aggregator) drainOperations(b *Batch, now time.Time, final bool) {
	cur := now.UTC().Truncate(time.Minute)
	for k, v := range a.ops {
		if !final && !k.minute.Before(cur) {
			continue
		}
		h := make([]int64, histLen)
		copy(h, v.hist[:])
		b.Operations = append(b.Operations, BatchOperation{Service: k.svc.name, Environment: k.svc.env, Kind: k.kind, Name: k.name,
			Minute: k.minute, Runs: v.runs, Failures: v.failures, DurBuckets: h, Sketch: sketchWire(v.sk), LastRun: v.last.UTC()})
		delete(a.ops, k)
	}
}
