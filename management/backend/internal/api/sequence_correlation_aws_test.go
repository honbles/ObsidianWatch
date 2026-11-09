package api

import (
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func awsSeqEv(name, user, ip, resp string, at time.Time) store.Event {
	return store.Event{EventType: "cloud.cloudtrail", Time: at, UserName: &user, SrcIP: &ip, Host: "us-east-1",
		Raw: []byte(`{"event_name":"` + name + `","response_elements":{"ConsoleLogin":"` + resp + `"}}`)}
}

func TestAWSSequenceRules(t *testing.T) {
	now := time.Now()
	c := newSeqCorrelator()
	if h := c.Observe(awsSeqEv("ConsoleLogin", "bob", "8.8.8.8", "Failure", now)); len(h) != 0 {
		t.Fatalf("unexpected %v", h)
	}
	h := c.Observe(awsSeqEv("ConsoleLogin", "bob", "8.8.8.8", "Success", now.Add(time.Minute)))
	if len(h) != 1 || h[0].Rule != "CORR-SEQ-AWS-001" {
		t.Fatalf("login seq: %+v", h)
	}
	c = newSeqCorrelator()
	c.Observe(awsSeqEv("CreateAccessKey", "arn:aws:sts::1:assumed-role/R/s1", "8.8.8.8", "", now))
	h = c.Observe(awsSeqEv("AttachUserPolicy", "arn:aws:sts::1:assumed-role/R/s2", "8.8.8.8", "", now.Add(time.Minute)))
	if len(h) != 1 || h[0].Rule != "CORR-SEQ-AWS-002" {
		t.Fatalf("persistence seq (sessions must fold to the role): %+v", h)
	}
	c = newSeqCorrelator()
	c.Observe(awsSeqEv("StopLogging", "eve", "1.2.3.4", "", now))
	if h = c.Observe(awsSeqEv("CreateUser", "mallory", "1.2.3.4", "", now.Add(time.Minute))); len(h) != 0 {
		t.Fatal("different actors must not correlate")
	}
	if h = c.Observe(awsSeqEv("CreateUser", "eve", "1.2.3.4", "", now.Add(2*time.Minute))); len(h) != 1 {
		t.Fatalf("tamper seq: %+v", h)
	}
	if h = c.Observe(awsSeqEv("ConsoleLogin", "x", "10.0.0.1", "Success", now)); len(h) != 0 {
		t.Fatal("private IP must not key a rule")
	}
}
