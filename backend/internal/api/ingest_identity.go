package api

import (
	"bytes"
	"encoding/json"
	"strings"

	"obsidianwatch/backend/pkg/schema"
)

// liftProcessIdentity fills ProcessGUID / ParentProcessGUID (and LogonID for
// Sysmon events) from the raw payload when the agent did not set them, so the
// Alert Graph can join on exact process instances without agent redeploys.
//
// Sources, in order: top-level keys written by the Linux/macOS agents
// (process_guid, parent_process_guid) and Sysmon event_data (ProcessGuid,
// ParentProcessGuid; SourceProcessGuid for the acting process of events 8/10).
func liftProcessIdentity(e *schema.Event) {
	if len(e.Raw) == 0 {
		return
	}
	// Cheap pre-check: nearly every non-process event has none of these.
	if !bytes.Contains(e.Raw, []byte("uid")) && !bytes.Contains(e.Raw, []byte("UID")) &&
		!bytes.Contains(e.Raw, []byte("LogonId")) {
		return
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(e.Raw, &m) != nil {
		return
	}
	var ed map[string]string
	if v, ok := m["event_data"]; ok {
		_ = json.Unmarshal(v, &ed)
	}
	look := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				var s string
				if json.Unmarshal(v, &s) == nil && s != "" {
					return s
				}
			}
			if s := ed[k]; s != "" {
				return s
			}
		}
		return ""
	}
	if e.ProcessGUID == "" {
		e.ProcessGUID = capStr(look("process_guid", "ProcessGuid", "ProcessGUID", "SourceProcessGuid", "SourceProcessGUID"), 128)
	}
	if e.ParentProcessGUID == "" {
		e.ParentProcessGUID = capStr(look("parent_process_guid", "ParentProcessGuid", "ParentProcessGUID"), 128)
	}
	// Sysmon carries the session's logon id as "LogonId" (0x...). Security
	// 4624 uses 0x... too; keep one normalised lowercase form for joins.
	if e.LogonID == "" {
		if v := look("LogonId", "LogonID"); v != "" {
			e.LogonID = capStr(strings.ToLower(v), 64)
		}
	} else {
		e.LogonID = strings.ToLower(e.LogonID)
	}
}
