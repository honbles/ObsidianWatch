package api

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func ceToEvent(c CloudEvent) store.Event {
	ev := store.Event{ID: c.ID, Time: c.Time, AgentID: c.AgentID, Host: c.Host, OS: c.OS,
		EventType: c.EventType, Severity: c.Severity, Source: c.Source, Raw: c.Raw}
	if c.Username != "" {
		u := c.Username
		ev.UserName = &u
	}
	return ev
}

func devSig(t *testing.T, id string) ThreatSig {
	t.Helper()
	for _, s := range devopsSignatures {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no sig %s", id)
	return ThreatSig{}
}

func TestGitHubRepoScope(t *testing.T) {
	if !githubRepoBelongs("Acme/api", "acme") || githubRepoBelongs("someone/api", "acme") || githubRepoBelongs("noslash", "acme") {
		t.Fatal("githubRepoBelongs")
	}
	urls := githubRepoListURLs("a b")
	if len(urls) != 2 || urls[0] != "https://api.github.com/orgs/a%20b/repos?per_page=100&sort=pushed&type=all" {
		t.Fatalf("urls: %v", urls)
	}
}

func TestGitHubOrganizationWebhook(t *testing.T) {
	conn := &store.DevOpsConnector{ID: 3, Org: "acme"}
	evs := processGitHubWebhookEvent("organization", map[string]interface{}{
		"action":     "member_added",
		"sender":     map[string]interface{}{"login": "boss"},
		"membership": map[string]interface{}{"role": "admin", "user": map[string]interface{}{"login": "newbie"}},
	}, conn)
	if len(evs) != 1 || evs[0].EventType != "devops.org_member_added" || evs[0].Severity < 4 {
		t.Fatalf("org webhook: %+v", evs)
	}
	if !devSig(t, "DEV-009").Match(ceToEvent(evs[0])) {
		t.Fatal("DEV-009 should match an admin added through the organization webhook")
	}
}

func TestWorkflowRunForkDetection(t *testing.T) {
	run := func(trigger, head, action string) store.Event {
		evs := processGitHubWebhookEvent("workflow_run", map[string]interface{}{
			"action":     action,
			"repository": map[string]interface{}{"full_name": "acme/api"},
			"workflow_run": map[string]interface{}{
				"event": trigger, "head_branch": "patch-1",
				"head_repository": map[string]interface{}{"full_name": head},
			},
		}, &store.DevOpsConnector{ID: 1, Org: "acme"})
		return ceToEvent(evs[0])
	}
	dev5 := devSig(t, "DEV-005")
	if !dev5.Match(run("pull_request_target", "evil/api", "requested")) {
		t.Fatal("fork + pull_request_target must alert")
	}
	if dev5.Match(run("pull_request_target", "evil/api", "in_progress")) {
		t.Fatal("in_progress is the same run")
	}
	if dev5.Match(run("pull_request", "evil/api", "completed")) {
		t.Fatal("pull_request from a fork runs without secrets")
	}
	if dev5.Match(run("pull_request_target", "acme/api", "completed")) {
		t.Fatal("same-repo branch is not a fork")
	}
}

func TestDEV007OnlyRepoDeletion(t *testing.T) {
	dev7 := devSig(t, "DEV-007")
	for _, c := range []struct {
		typ, raw string
		want     bool
	}{
		{"devops.repo_deleted", `{"event":"repository.deleted"}`, true},
		{"devops.project_destroyed", `{}`, true},
		{"devops.deploy_key_deleted", `{"event":"deploy_key","action":"deleted"}`, false},
		{"devops.branch_protection_rule_deleted", `{"action":"deleted"}`, false},
	} {
		if got := dev7.Match(store.Event{EventType: c.typ, Raw: []byte(c.raw)}); got != c.want {
			t.Errorf("%s: got %v", c.typ, got)
		}
	}
}

func TestADOAuditCanonicalAndDEV022(t *testing.T) {
	conn := &store.DevOpsConnector{ID: 9, Org: "o"}
	evs := adoAuditToEvents([]map[string]interface{}{
		{"id": "1", "actionId": "Git.RepositoryDeleted", "timestamp": "2026-01-01T00:00:00Z"},
		{"id": "2", "actionId": "Library.ServiceConnectionCreated", "timestamp": "2026-01-01T00:00:00Z"},
		{"id": "3", "actionId": "Group.UpdateGroupMembership.Add", "data": map[string]interface{}{"GroupName": "Project Collection Administrators"}},
	}, conn)
	if len(evs) != 3 {
		t.Fatalf("events: %+v", evs)
	}
	if !devSig(t, "DEV-007").Match(ceToEvent(evs[0])) {
		t.Fatal("ADO repository deletion should match DEV-007")
	}
	dev22 := devSig(t, "DEV-022")
	if dev22.Match(ceToEvent(evs[0])) || !dev22.Match(ceToEvent(evs[1])) {
		t.Fatal("DEV-022 covers what specific rules do not")
	}
	if !devSig(t, "DEV-009").Match(ceToEvent(evs[2])) {
		t.Fatal("admin group membership should match DEV-009")
	}
}

func TestGitLabAuditEventsParsed(t *testing.T) {
	conn := &store.DevOpsConnector{ID: 2, Org: "g/sub"}
	evs := gitlabAuditToEvents([]map[string]interface{}{
		{"id": float64(11), "created_at": "2026-01-01T00:00:00Z", "details": map[string]interface{}{
			"add": "user_access", "as": "Owner", "author_name": "root", "entity_path": "g/sub", "ip_address": "1.2.3.4"}},
		{"id": float64(12), "details": map[string]interface{}{"change": "visibility", "from": "Private", "to": "Public", "author_name": "root"}},
		{"id": float64(13), "event_name": "project_destroyed", "details": map[string]interface{}{"remove": "project", "author_name": "root"}},
	}, conn)
	if len(evs) != 3 || evs[0].Username != "root" || evs[0].SrcIP != "1.2.3.4" {
		t.Fatalf("gitlab audit: %+v", evs)
	}
	if !devSig(t, "DEV-009").Match(ceToEvent(evs[0])) || !devSig(t, "DEV-006").Match(ceToEvent(evs[1])) ||
		!devSig(t, "DEV-007").Match(ceToEvent(evs[2])) {
		t.Fatal("gitlab audit events should reach DEV-009/006/007")
	}
	if gitlabID("g/sub proj") != "g%2Fsub%20proj" {
		t.Fatalf("gitlabID: %s", gitlabID("g/sub proj"))
	}
}

func TestSARIFSeverity(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"9.8", ""}: "critical", {"7.5", "warning"}: "high", {"5.0", ""}: "medium", {"2", ""}: "low",
		{"", "error"}: "high", {"", "warning"}: "medium", {"", "note"}: "low", {"", "recommendation"}: "low", {"", ""}: "",
	} {
		if got := sarifSeverity(in[0], in[1]); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
}

func TestAsyncJobKeyIncludesQuery(t *testing.T) {
	a := asyncJobKey(httptest.NewRequest("POST", "/api/v1/devops-connectors/1/sast?async=1&repo=a/x", nil))
	b := asyncJobKey(httptest.NewRequest("POST", "/api/v1/devops-connectors/1/sast?repo=b/x&async=1", nil))
	c := asyncJobKey(httptest.NewRequest("POST", "/api/v1/devops-connectors/1/sast?repo=a/x", nil))
	if a == b || a != c {
		t.Fatalf("keys: %q %q %q", a, b, c)
	}
}

func TestDevOpsDedupKeyPerRepo(t *testing.T) {
	at := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	mk := func(raw string) store.Event {
		return store.Event{AgentID: "devops:1", Host: "acme", Time: at, EventType: "devops.secret_push", Raw: []byte(raw)}
	}
	a := devopsDedupKey("DEV-001", mk(`{"repo":"acme/a","file":".env"}`))
	b := devopsDedupKey("DEV-001", mk(`{"repo":"acme/b","file":".env"}`))
	a2 := devopsDedupKey("DEV-001", mk(`{"repo":"acme/a","file":".env","sha":"x"}`))
	if a == b || a != a2 {
		t.Fatalf("keys: %s %s %s", a, b, a2)
	}
}

func TestCodeFindingDedupKeepsRepos(t *testing.T) {
	out := deduplicateFindings([]CodeFinding{
		{Repo: "a", Category: "secret", Title: "AWS key", File: ".env"},
		{Repo: "b", Category: "secret", Title: "AWS key", File: ".env"},
		{Repo: "a", Category: "secret", Title: "AWS key", File: ".env"},
	})
	if len(out) != 2 {
		t.Fatalf("got %d", len(out))
	}
}

func TestDevOpsDialGuard(t *testing.T) {
	t.Setenv("OW_ALLOW_PRIVATE_DEVOPS", "")
	for addr, ok := range map[string]bool{
		"127.0.0.1": false, "169.254.169.254": false, "10.0.0.5": false, "::1": false, "0.0.0.0": false,
		"140.82.112.3": true, "2606:50c0:8000::153": true,
	} {
		if err := devopsAddrAllowed(netip.MustParseAddr(addr)); (err == nil) != ok {
			t.Errorf("%s: err=%v", addr, err)
		}
	}
	t.Setenv("OW_ALLOW_PRIVATE_DEVOPS", "true")
	if devopsAddrAllowed(netip.MustParseAddr("10.0.0.5")) != nil || devopsAddrAllowed(netip.MustParseAddr("127.0.0.1")) == nil {
		t.Fatal("private allowed only by opt-in; loopback never")
	}
}

func TestADOClientHonoursBaseURLAndProject(t *testing.T) {
	c := adoClientFor(&store.DevOpsConnector{Org: "coll", Credentials: map[string]string{"base_url": "https://tfs.example.com/tfs/DefaultCollection/"}})
	if c.baseURL != "https://tfs.example.com/tfs/DefaultCollection" || c.adoIsCloud() {
		t.Fatalf("base: %s", c.baseURL)
	}
	if !adoClientFor(&store.DevOpsConnector{Org: "my org", Credentials: map[string]string{}}).adoIsCloud() {
		t.Fatal("default is cloud")
	}
	ps, err := adoProjects(t.Context(), c, &store.DevOpsConnector{Credentials: map[string]string{"project": " Web "}})
	if err != nil || len(ps) != 1 || ps[0] != "Web" {
		t.Fatalf("projects: %v %v", ps, err)
	}
}

func TestDevOpsRedirectDropsCredentials(t *testing.T) {
	first := httptest.NewRequest("GET", "https://gitlab.example.com/a", nil)
	next := httptest.NewRequest("GET", "https://cdn.example.net/b", nil)
	next.Header.Set("PRIVATE-TOKEN", "x")
	next.Header.Set("Authorization", "Bearer x")
	if err := devopsHTTP.CheckRedirect(next, []*http.Request{first}); err != nil || next.Header.Get("PRIVATE-TOKEN") != "" || next.Header.Get("Authorization") != "" {
		t.Fatalf("cross-host redirect: %v %v", err, next.Header)
	}
	plain := httptest.NewRequest("GET", "http://gitlab.example.com/b", nil)
	if devopsHTTP.CheckRedirect(plain, []*http.Request{first}) == nil {
		t.Fatal("http redirect must stop")
	}
}
