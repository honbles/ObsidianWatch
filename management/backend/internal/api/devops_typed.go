package api

import (
	"encoding/json"
	"strings"

	"obsidianwatch/management/internal/store"
)

// DS-08: typed view of a DevOps event. Rules used to lower-case the whole raw
// JSON and look for substrings anywhere in it ("runner" in a commit message,
// "owner" in a repo name...). devopsTyped parses the few fields providers
// actually put the action in, so rules compare exact values.
type devopsTyped struct {
	Action     string // normalised "action" (audit log) or "event" (webhook), lower-case
	Event      string
	Visibility string
	Role       string
	Branch     string
	Type       string // runner type etc.
}

func devopsParse(ev store.Event) devopsTyped {
	var m struct {
		Action     string `json:"action"`
		Event      string `json:"event"`
		Visibility string `json:"visibility"`
		Role       string `json:"role"`
		Permission string `json:"permission"`
		Branch     string `json:"branch"`
		Type       string `json:"type"`
	}
	_ = json.Unmarshal(ev.Raw, &m)
	t := devopsTyped{
		Action:     strings.ToLower(m.Action),
		Event:      strings.ToLower(m.Event),
		Visibility: strings.ToLower(m.Visibility),
		Role:       strings.ToLower(m.Role),
		Branch:     m.Branch,
		Type:       strings.ToLower(m.Type),
	}
	if t.Role == "" {
		t.Role = strings.ToLower(m.Permission)
	}
	return t
}

// is reports whether the action or event equals any of the given values, or
// the event type's suffix does (devops.repo_deleted -> repo_deleted).
func (t devopsTyped) is(ev store.Event, values ...string) bool {
	suffix := strings.TrimPrefix(string(ev.EventType), "devops.")
	for _, v := range values {
		if t.Action == v || t.Event == v || suffix == v {
			return true
		}
	}
	return false
}
