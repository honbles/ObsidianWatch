package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestSoftwareContainerSigs(t *testing.T) {
	m := func(id string, ev store.Event) bool {
		for _, s := range softwareSignatures {
			if s.ID == id {
				return s.Match(ev)
			}
		}
		t.Fatalf("missing %s", id)
		return false
	}
	if !m("L-SW-001", store.Event{EventType: "software", Raw: []byte(`{"action":"software_installed","package":"nmap"}`)}) {
		t.Error("nmap install should match")
	}
	if m("L-SW-001", store.Event{EventType: "software", Raw: []byte(`{"action":"software_removed","package":"nmap"}`)}) {
		t.Error("removal should not match")
	}
	if m("L-SW-001", store.Event{EventType: "software", Raw: []byte(`{"action":"software_installed","package":"vim"}`)}) {
		t.Error("vim should not match")
	}
	if !m("L-CTR-001", store.Event{EventType: "container", Raw: []byte(`{"container":{"risks":["privileged"]}}`)}) {
		t.Error("privileged container should match")
	}
	if m("L-CTR-001", store.Event{EventType: "container", Raw: []byte(`{"container":{"risks":[]}}`)}) {
		t.Error("clean container should not match")
	}
}
