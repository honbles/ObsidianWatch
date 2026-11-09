package api

import (
	"encoding/json"
	"testing"

	"obsidianwatch/management/internal/store"
)

// H-01: structural sanity and panic-safety over every signature set.
func everySigSets() map[string][]ThreatSig { return allSignatureSets() }

func TestEverySignatureWellFormed(t *testing.T) {
	seen := map[string]string{}
	for name, set := range everySigSets() {
		for _, s := range set {
			if s.ID == "" || s.Name == "" || s.Match == nil {
				t.Errorf("%s: incomplete sig %q", name, s.ID)
			}
			if s.Severity < 1 || s.Severity > 5 {
				t.Errorf("%s/%s: severity %d out of range", name, s.ID, s.Severity)
			}
			if prev, ok := seen[s.ID]; ok && prev != name {
				t.Errorf("duplicate ID %s in %s and %s", s.ID, prev, name)
			}
			seen[s.ID] = name
		}
	}
}

func TestSignaturesNeverPanicOnOddEvents(t *testing.T) {
	empty := ""
	zero := 0
	events := []store.Event{
		{},
		{EventType: "cloud.aws_cloudtrail", Raw: json.RawMessage(`not json`)},
		{EventType: "cloud.azure_activity", Raw: json.RawMessage(`{}`), UserName: &empty},
		{EventType: "cloud.gcp_audit", Raw: json.RawMessage(`{"proto_payload":null}`), PID: &zero},
		{EventType: "process", CommandLine: &empty, ImagePath: &empty, Raw: json.RawMessage(`[]`)},
		{EventType: "network", Raw: json.RawMessage(`"str"`)},
	}
	for name, set := range everySigSets() {
		for _, s := range set {
			for i, ev := range events {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("%s/%s panicked on event %d: %v", name, s.ID, i, r)
						}
					}()
					s.Match(ev)
				}()
			}
		}
	}
}
