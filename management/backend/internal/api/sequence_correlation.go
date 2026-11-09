package api

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// D-07 (sequences): "A then B on the same entity within a window" rules.
// State is in memory and time-pruned; alerts reuse the dedup path of the auth
// correlator (raiseAuthHits).

type seqRule struct {
	ID, Title, Desc, MITRE string
	Severity               int
	Window                 time.Duration
	A, B                   func(store.Event) bool
	Key                    func(store.Event) string // entity both steps share
}

func hostKey(ev store.Event) string { return strings.ToLower(ev.Host) }

var seqRules = []seqRule{
	{
		ID: "CORR-SEQ-001", Title: "Account created then added to a privileged group",
		Desc:  "A local account was created and, shortly after, a member was added to a security group on the same host (Windows 4720 → 4732/4728). This is the classic persistence pattern.",
		MITRE: "T1136.001,T1098", Severity: 4, Window: 30 * time.Minute, Key: hostKey,
		A: func(ev store.Event) bool { return winEventIs(ev, 4720) },
		B: func(ev store.Event) bool { return winEventIs(ev, 4732, 4728, 4756) },
	},
	{
		ID: "CORR-SEQ-002", Title: "Linux account created then given privileged group membership",
		Desc:  "useradd/adduser was followed by a privileged group change (sudo/wheel/admin/docker/root) on the same host within 30 minutes.",
		MITRE: "T1136.001,T1098", Severity: 4, Window: 30 * time.Minute, Key: hostKey,
		A: func(ev store.Event) bool {
			return ev.EventType == "process" && ev.ProcessName != nil &&
				containsAny(strings.ToLower(*ev.ProcessName), "useradd", "adduser")
		},
		B: func(ev store.Event) bool { return linuxAccountSignatures[1].Match(ev) },
	},
	{
		ID: "CORR-SEQ-003", Title: "Audit log cleared after account or privilege change",
		Desc:  "The Windows Security log was cleared (1102) within an hour of an account or group change on the same host — a common attempt to hide persistence.",
		MITRE: "T1070.001", Severity: 5, Window: time.Hour, Key: hostKey,
		A: func(ev store.Event) bool { return winEventIs(ev, 4720, 4732, 4728, 4724) },
		B: func(ev store.Event) bool { return winEventIs(ev, 1102) },
	},
	{
		ID: "CORR-SEQ-AWS-001", Title: "AWS console login succeeded after a failed attempt from the same IP",
		Desc:  "A failed AWS console login was followed by a successful one from the same source IP within 15 minutes — possible password guessing or credential stuffing that worked.",
		MITRE: "T1110", Severity: 4, Window: 15 * time.Minute, Key: awsSrcIPKey,
		A: func(ev store.Event) bool {
			return awsEventIs(ev, "consolelogin") && awsRawHas(ev, `"consolelogin":"failure"`) && awsSrcIPKey(ev) != ""
		},
		B: func(ev store.Event) bool {
			return awsEventIs(ev, "consolelogin") && awsRawHas(ev, `"consolelogin":"success"`) && awsSrcIPKey(ev) != ""
		},
	},
	{
		ID: "CORR-SEQ-AWS-002", Title: "AWS identity created or given a key, then granted permissions",
		Desc:  "The same AWS principal created a user or access key and then attached/put a policy or added a user to a group within 30 minutes — a common persistence and privilege-escalation sequence.",
		MITRE: "T1136.003,T1098", Severity: 4, Window: 30 * time.Minute, Key: awsActorKey,
		A: func(ev store.Event) bool {
			return awsEventIs(ev, "createuser", "createaccesskey") && awsActorKey(ev) != ""
		},
		B: func(ev store.Event) bool {
			return awsEventIs(ev, "attachuserpolicy", "putuserpolicy", "addusertogroup", "attachrolepolicy", "putrolepolicy") && awsActorKey(ev) != ""
		},
	},
	{
		ID: "CORR-SEQ-AWS-003", Title: "AWS logging tampered with, then new resources or identities created",
		Desc:  "The same AWS principal stopped, deleted or changed CloudTrail and then created identities or compute within an hour — activity that may have been hidden from audit.",
		MITRE: "T1562.008", Severity: 5, Window: time.Hour, Key: awsActorKey,
		A: func(ev store.Event) bool {
			return awsEventIs(ev, "stoplogging", "deletetrail", "updatetrail", "puteventselectors") && awsActorKey(ev) != ""
		},
		B: func(ev store.Event) bool {
			return awsEventIs(ev, "createuser", "createaccesskey", "runinstances", "createrole") && awsActorKey(ev) != ""
		},
	},
}

// ── AWS helpers for sequence rules ──

func awsEventIs(ev store.Event, names ...string) bool {
	if ev.EventType != "cloud.cloudtrail" || len(ev.Raw) == 0 {
		return false
	}
	m := awsEventNameRe.FindStringSubmatch(rawStr(ev))
	if m == nil {
		return false
	}
	for _, n := range names {
		if m[1] == n {
			return true
		}
	}
	return false
}

func awsRawHas(ev store.Event, sub string) bool { return strings.Contains(rawStr(ev), sub) }

func awsActorKey(ev store.Event) string { return strings.ToLower(awsPrincipal(ev)) }

func awsSrcIPKey(ev store.Event) string {
	if ev.SrcIP != nil && awsPublicIP(*ev.SrcIP) {
		return *ev.SrcIP
	}
	return ""
}

type seqCorrelator struct {
	mu    sync.Mutex
	state map[string]time.Time // rule|key -> last A
}

func newSeqCorrelator() *seqCorrelator { return &seqCorrelator{state: map[string]time.Time{}} }

func (c *seqCorrelator) Observe(ev store.Event) []authHit {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.state) > 50000 {
		c.state = map[string]time.Time{}
	}
	var hits []authHit
	for _, r := range seqRules {
		k := r.ID + "|" + r.Key(ev)
		if r.B(ev) {
			if at, ok := c.state[k]; ok && ev.Time.Sub(at) >= 0 && ev.Time.Sub(at) <= r.Window {
				hits = append(hits, authHit{
					Rule: r.ID, Title: fmt.Sprintf("%s on %s", r.Title, ev.Host), Desc: r.Desc,
					Severity: r.Severity, MITRE: r.MITRE, Entity: "seq|" + k,
					Bucket: ev.Time.Unix() / int64(r.Window.Seconds()),
				})
				delete(c.state, k)
			}
		}
		if r.A(ev) {
			c.state[k] = ev.Time
		}
	}
	return hits
}
