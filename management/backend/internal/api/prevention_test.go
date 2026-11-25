package api

import (
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestBuildPrevSetProtectsAndCaps(t *testing.T) {
	now := time.Now()
	later := now.Add(48 * time.Hour)
	pol := defaultPreventionPolicy()
	pol.MaxIPs = 2
	c := []store.PreventionCandidate{
		{Type: "ip", Value: "45.9.148.10", Source: "manual", Until: later},
		{Type: "ip", Value: "45.9.148.10", Source: "threatfox", Until: later.Add(time.Hour)}, // duplicate: keeps the longer expiry
		{Type: "ip", Value: "10.0.0.5", Source: "threatfox", Until: later},                   // private
		{Type: "ip", Value: "8.8.8.8", Source: "threatfox", Until: later},                    // resolver
		{Type: "ip", Value: "100.64.1.1", Source: "threatfox", Until: later},                 // CGNAT
		{Type: "ip", Value: "185.220.101.1", Source: "feodo", Until: later},
		{Type: "ip", Value: "185.220.101.2", Source: "feodo", Until: later}, // over the cap
		{Type: "ip", Value: "185.220.101.3", Source: "feodo", Until: now.Add(-time.Hour)},
		{Type: "domain", Value: "evil-c2.example.", Source: "threatfox", Until: later},
		{Type: "domain", Value: "files.github.com", Source: "threatfox", Until: later}, // shared platform
		{Type: "hash", Value: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", Source: "threatfox", Until: later},
		{Type: "hash", Value: "aa" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", Source: "threatfox", Until: later},
		{Type: "hash", Value: "zz" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", Source: "threatfox", Until: later}, // not hex
	}
	set := buildPrevSet(c, pol, now)
	if len(set.IPs) != 2 || set.IPs[0].V != "45.9.148.10" || set.IPs[0].Until != later.Add(time.Hour).Unix() {
		t.Fatalf("ips %+v", set.IPs)
	}
	if len(set.Truncated) != 1 || set.Truncated[0] != "ip" {
		t.Fatalf("truncated %v", set.Truncated)
	}
	if len(set.Domains) != 1 || set.Domains[0].V != "evil-c2.example" {
		t.Fatalf("domains %+v", set.Domains)
	}
	if len(set.Hashes) != 1 { // empty-file and non-hex hashes dropped
		t.Fatalf("hashes %+v", set.Hashes)
	}
	if set.Dropped != 6 {
		t.Fatalf("dropped %d", set.Dropped)
	}
	if set.Version == "" || buildPrevSet(c, pol, now).Version != set.Version {
		t.Fatal("version must be stable for the same content")
	}
}

func TestModesForCanary(t *testing.T) {
	pol := defaultPreventionPolicy()
	pol.IP, pol.Hash = PrevEnforce, PrevEnforce
	pol.EnforceTags = []string{"canary"}
	if m := modesFor(pol, []string{"web"}); m["ip"] != PrevAudit || m["domain"] != PrevAudit {
		t.Fatalf("untagged host enforces: %v", m)
	}
	if m := modesFor(pol, []string{"Canary"}); m["ip"] != PrevEnforce || m["hash"] != PrevEnforce || m["domain"] != PrevAudit {
		t.Fatalf("canary host: %v", m)
	}
	pol.EnforceTags = nil
	if m := modesFor(pol, nil); m["ip"] != PrevEnforce {
		t.Fatalf("no tags configured means every host: %v", m)
	}
}

func TestPolicyNormalise(t *testing.T) {
	p := PreventionPolicy{IP: "block", MinConfidence: 5, MaxIPs: 10_000_000}
	p.normalise()
	if p.IP != PrevAudit || p.MinConfidence != 75 || p.MaxIPs != 100000 || p.MaxAgeDays != 90 {
		t.Fatalf("%+v", p)
	}
}

func TestPreventionSignatures(t *testing.T) {
	ev := func(kind, action string) store.Event {
		return store.Event{EventType: "prevention", Raw: []byte(`{"kind":"` + kind + `","action":"` + action + `"}`)}
	}
	cases := map[string]store.Event{
		"PREV-IP-1": ev("ip", "blocked"), "PREV-IP-0": ev("ip", "audit"),
		"PREV-HASH-1": ev("hash", "killed+quarantined"), "PREV-HASH-0": ev("hash", "failed"),
		"PREV-DNS-1": ev("domain", "ip_blocked"), "PREV-DNS-0": ev("domain", "audit"),
	}
	for id, e := range cases {
		hits := 0
		for _, s := range preventionSignatures {
			if s.Match(e) {
				hits++
				if s.ID != id {
					t.Errorf("%s matched by %s", id, s.ID)
				}
			}
		}
		if hits != 1 {
			t.Errorf("%s: %d rules matched", id, hits)
		}
	}
}
