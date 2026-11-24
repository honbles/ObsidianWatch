package api

// match_helpers.go - shared matchers so rules stop doing substring matches on
// the concatenation of process name + command line + file path (FP-reduction B).

import (
	"encoding/json"
	"strings"

	"obsidianwatch/management/internal/store"
)

func pathBase(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(p), ".exe")
}

// exeBase is the lower-case base name of the executable: raw "exe", then
// ImagePath, then ProcessName. For shebang scripts the kernel comm is the
// script name, so the raw exe (the interpreter) must win.
func exeBase(ev store.Event) string {
	if len(ev.Raw) > 0 {
		var r struct {
			Exe string `json:"exe"`
		}
		if json.Unmarshal(ev.Raw, &r) == nil && r.Exe != "" {
			return pathBase(r.Exe)
		}
	}
	if ev.ImagePath != nil && *ev.ImagePath != "" {
		return pathBase(*ev.ImagePath)
	}
	if ev.ProcessName != nil {
		return pathBase(*ev.ProcessName)
	}
	return ""
}

// exeIn reports whether exeBase or the process name equals one of names.
func exeIn(ev store.Event, names ...string) bool {
	b := exeBase(ev)
	for _, n := range names {
		if b == n {
			return true
		}
	}
	return procIn(ev, names...)
}

// argv returns raw["argv"] when the agent supplied it, else the original-case
// command line split on whitespace.
func argv(ev store.Event) []string {
	if len(ev.Raw) > 0 {
		var r struct {
			Argv []string `json:"argv"`
		}
		if json.Unmarshal(ev.Raw, &r) == nil && len(r.Argv) > 0 {
			return r.Argv
		}
	}
	if ev.CommandLine == nil {
		return nil
	}
	return strings.Fields(*ev.CommandLine)
}

// hasToken is true if any argv element equals one of toks (case-insensitive).
func hasToken(ev store.Event, toks ...string) bool {
	for _, a := range argv(ev) {
		for _, t := range toks {
			if strings.EqualFold(a, t) {
				return true
			}
		}
	}
	return false
}

func isType(ev store.Event, types ...string) bool {
	for _, t := range types {
		if ev.EventType == t {
			return true
		}
	}
	return false
}

// origCL is the command line with its original case.
func origCL(ev store.Event) string {
	if ev.CommandLine == nil {
		return ""
	}
	return *ev.CommandLine
}

// shellPayload returns the payload of `sh|bash|dash|zsh ... -c <payload>`.
func shellPayload(ev store.Event) string {
	a := argv(ev)
	for i, tok := range a {
		if strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "--") && strings.Contains(tok, "c") && i+1 < len(a) {
			return strings.Join(a[i+1:], " ")
		}
	}
	return ""
}

// rawStringField returns a top-level string field of the event's raw JSON.
func rawStringField(ev store.Event, key string) string {
	if len(ev.Raw) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(ev.Raw, &m) != nil {
		return ""
	}
	var s string
	if v, ok := m[key]; ok && json.Unmarshal(v, &s) == nil {
		return s
	}
	return ""
}

// imdsAllowedProcess: cloud guest agents and cloud CLIs that legitimately read
// the instance metadata service.
// Extended by the `imds_allowed_processes` setting (see setIMDSExtraAllowed).
func imdsAllowedProcess(ev store.Event) bool {
	return exeIn(ev, "cloud-init", "cloud-init-local", "google_guest_agent", "google_osconfig_agent",
		"amazon-ssm-agent", "ssm-agent-worker", "waagent", "aws", "az", "gcloud", "chronyd") || imdsExtraAllowedFor(ev)
}
