package api

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func authEv(host, user, ip, action string, t time.Time) store.Event {
	raw, _ := json.Marshal(map[string]string{"action": action})
	return store.Event{Time: t, Host: host, OS: "linux", EventType: "logon", UserName: &user, SrcIP: &ip, Raw: raw}
}

func TestAuthSpray(t *testing.T) {
	c := newAuthCorrelator()
	t0 := time.Now()
	var got []authHit
	for i := 0; i < 10; i++ {
		got = append(got, c.Observe(authEv("h", fmt.Sprintf("u%d", i), "1.2.3.4", "ssh_login_failure", t0.Add(time.Duration(i)*time.Second)))...)
	}
	found := false
	for _, h := range got {
		if h.Rule == "CORR-AUTH-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected spray hit")
	}
}

func TestAuthSuccessAfterFailures(t *testing.T) {
	c := newAuthCorrelator()
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		c.Observe(authEv("h", "bob", "9.9.9.9", "ssh_login_failure", t0.Add(time.Duration(i)*time.Second)))
	}
	hits := c.Observe(authEv("h", "bob", "9.9.9.9", "ssh_login_success", t0.Add(10*time.Second)))
	if len(hits) != 1 || hits[0].Rule != "CORR-AUTH-003" {
		t.Fatalf("got %+v", hits)
	}
}

func TestAuthWindowExpiry(t *testing.T) {
	c := newAuthCorrelator()
	t0 := time.Now()
	for i := 0; i < 9; i++ {
		c.Observe(authEv("h", "al", "5.5.5.5", "ssh_login_failure", t0.Add(time.Duration(i)*time.Second)))
	}
	if h := c.Observe(authEv("h", "al", "5.5.5.5", "ssh_login_failure", t0.Add(10*time.Minute))); len(h) != 0 {
		t.Fatalf("expired failures should not count: %+v", h)
	}
}

func TestEntraIdentitySigs(t *testing.T) {
	mk := func(raw string) store.Event {
		return store.Event{EventType: "cloud.entra_signin", Raw: json.RawMessage(raw)}
	}
	cases := map[string]string{
		"C-AZ-ID-001": `{"risk_state":"atRisk","status":{"errorCode":0}}`,
		"C-AZ-ID-002": `{"client_app_used":"IMAP4","status":{"errorCode":0}}`,
		"C-AZ-ID-003": `{"conditional_access_status":"notApplied","status":{"errorCode":0}}`,
		"C-AZ-ID-004": `{"risk_level":"high","status":{"errorCode":50126}}`,
	}
	for id, raw := range cases {
		hit := false
		for _, s := range entraIdentitySignatures {
			if s.ID == id && s.Match(mk(raw)) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s did not match", id)
		}
	}
	for _, s := range entraIdentitySignatures {
		if s.Match(mk(`{"client_app_used":"Browser","conditional_access_status":"success","status":{"errorCode":0}}`)) {
			t.Errorf("%s false positive", s.ID)
		}
	}
}

func TestMFAFatigue(t *testing.T) {
	c := newAuthCorrelator()
	u := "carol@corp.com"
	t0 := time.Now()
	var hits []authHit
	for i := 0; i < 5; i++ {
		raw, _ := json.Marshal(map[string]interface{}{"status": map[string]int{"errorCode": 500121}})
		hits = append(hits, c.Observe(store.Event{Time: t0.Add(time.Duration(i) * time.Second), AgentID: "az", Host: "carol", EventType: "cloud.entra_signin", UserName: &u, Raw: raw})...)
	}
	if len(hits) != 1 || hits[0].Rule != "CORR-AUTH-004" {
		t.Fatalf("got %+v", hits)
	}
}

func TestSequenceAccountThenGroup(t *testing.T) {
	c := newSeqCorrelator()
	t0 := time.Now()
	id1, id2 := uint32(4720), uint32(4732)
	if h := c.Observe(store.Event{Host: "srv1", EventID: &id1, Time: t0}); len(h) != 0 {
		t.Fatal("A alone must not alert")
	}
	h := c.Observe(store.Event{Host: "srv1", EventID: &id2, Time: t0.Add(5 * time.Minute)})
	if len(h) != 1 || h[0].Rule != "CORR-SEQ-001" {
		t.Fatalf("got %+v", h)
	}
	// different host: no alert
	c.Observe(store.Event{Host: "srv2", EventID: &id1, Time: t0})
	if h := c.Observe(store.Event{Host: "srv3", EventID: &id2, Time: t0.Add(time.Minute)}); len(h) != 0 {
		t.Fatal("different host must not correlate")
	}
	// outside window: no alert
	c.Observe(store.Event{Host: "srv4", EventID: &id1, Time: t0})
	if h := c.Observe(store.Event{Host: "srv4", EventID: &id2, Time: t0.Add(2 * time.Hour)}); len(h) != 0 {
		t.Fatal("outside window must not alert")
	}
}
