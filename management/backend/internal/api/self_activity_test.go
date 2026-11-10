package api

import (
	"encoding/json"
	"testing"

	"obsidianwatch/management/internal/store"
)

func selfTestPtr(s string) *string { return &s }

func TestSelfActivityAndSysmon(t *testing.T) {
	if !isSelfActivity(store.Event{Raw: json.RawMessage(`{"a":1,"self_activity":true}`)}) {
		t.Fatal("tagged event must be self activity")
	}
	if isSelfActivity(store.Event{Raw: json.RawMessage(`{"self_activity":false}`)}) || isSelfActivity(store.Event{}) {
		t.Fatal("untagged event must not be self activity")
	}
	if !isOwnSysmon(store.Event{ProcessName: selfTestPtr("Sysmon64.exe"), ImagePath: sp(`C:\Windows\Sysmon64.exe`)}) {
		t.Fatal("installed Sysmon is ours")
	}
	if isOwnSysmon(store.Event{ProcessName: selfTestPtr("sysmon64.exe"), ImagePath: sp(`C:\Users\x\AppData\sysmon64.exe`)}) ||
		isOwnSysmon(store.Event{ProcessName: selfTestPtr("sysmon64.exe")}) {
		t.Fatal("renamed or pathless sysmon must still be analysed")
	}
}
