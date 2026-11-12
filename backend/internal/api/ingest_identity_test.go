package api

import (
	"encoding/json"
	"testing"

	"obsidianwatch/backend/pkg/schema"
)

func TestLiftProcessIdentity(t *testing.T) {
	cases := []struct {
		name, raw, logon, guid, pguid, wantLogon string
	}{
		{"sysmon", `{"event_data":{"ProcessGuid":"{A}","ParentProcessGuid":"{B}","LogonId":"0x3E7"}}`, "", "{A}", "{B}", "0x3e7"},
		{"sysmon access acting", `{"event_data":{"SourceProcessGuid":"{S}","TargetProcessGuid":"{T}"}}`, "", "{S}", "", ""},
		{"linux", `{"process_guid":"b-1-2","parent_process_guid":"b-0-1"}`, "", "b-1-2", "b-0-1", ""},
		{"normalise existing", `{"x":"uid"}`, "0xABC", "", "", "0xabc"},
		{"none", `{"foo":"bar"}`, "", "", "", ""},
	}
	for _, c := range cases {
		e := schema.Event{Raw: json.RawMessage(c.raw), LogonID: c.logon}
		liftProcessIdentity(&e)
		if e.ProcessGUID != c.guid || e.ParentProcessGUID != c.pguid || e.LogonID != c.wantLogon {
			t.Errorf("%s: got %q %q %q", c.name, e.ProcessGUID, e.ParentProcessGUID, e.LogonID)
		}
	}
	// agent-supplied values win
	e := schema.Event{Raw: json.RawMessage(`{"process_guid":"raw"}`), ProcessGUID: "agent"}
	liftProcessIdentity(&e)
	if e.ProcessGUID != "agent" {
		t.Errorf("agent value overwritten: %q", e.ProcessGUID)
	}
}
