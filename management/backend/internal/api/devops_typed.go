package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// devopsDedupKey is the alert key for a DevOps rule hit: one alert per rule,
// connector, day and entity, where the entity is the repository plus the
// actor plus the file or ref involved. alertEntityKey looks at process and
// network fields, which DevOps events never carry, so every hit of a rule on
// one connector used to collapse into a single alert per day: a secret pushed
// to repo B the same day as one in repo A was never raised.
func devopsDedupKey(sigID string, ev store.Event) string {
	var m struct {
		Repo   string `json:"repo"`
		File   string `json:"file"`
		Path   string `json:"path"`
		Branch string `json:"branch"`
		Ref    string `json:"ref"`
		Member string `json:"member"`
		Rule   string `json:"rule"`
	}
	_ = json.Unmarshal(ev.Raw, &m)
	actor := ""
	if ev.UserName != nil {
		actor = *ev.UserName
	}
	file := m.File
	if file == "" {
		file = m.Path
	}
	ref := m.Branch
	if ref == "" {
		ref = m.Ref
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.Join([]string{
		ev.AgentID, m.Repo, actor, file, ref, m.Member, m.Rule,
	}, "\x00"))))
	day := ev.Time.UTC().Format("20060102")
	return fmt.Sprintf("sig:%s:host:%s:d:%s:e:%s", sigID, ev.Host, day, hex.EncodeToString(sum[:])[:12])
}
