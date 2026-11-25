package api

import (
	"encoding/json"
	"errors"
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestAppServiceRole(t *testing.T) {
	cases := []struct {
		name   string
		attrs  string
		images []string
		tier   int
		role   string
		label  string
	}{
		{"postgres", `{}`, nil, 0, "database", "PostgreSQL"},
		{"php-fpm8.2", `{}`, nil, 0, "runtime", "PHP-FPM"},
		{"redis-server", `{}`, nil, 0, "cache", "Redis"},
		{"web", `{}`, []string{"docker.io/library/nginx:1.25"}, 0, "web", "nginx"},
		{"orders", `{"language":"java"}`, nil, 0, "app", ""},
		{"mystery", `{}`, nil, 0, "other", ""},
		{"checkout", `{}`, nil, 1, "app", ""},
	}
	for _, c := range cases {
		r := appServiceRole(c.name, json.RawMessage(c.attrs), c.images, c.tier)
		if r.Role != c.role || r.Label != c.label {
			t.Errorf("%s: got %+v want %s/%s", c.name, r, c.role, c.label)
		}
	}
}

func TestAppSortServices(t *testing.T) {
	list := []appServiceRow{
		{Name: "zz-tool", Tier: 0, RoleRank: 9},
		{Name: "nginx", Tier: 0, RoleRank: 3},
		{Name: "api", Tier: 1},
		{Name: "postgres", Tier: 0, RoleRank: 1},
		{Name: "shop", Tier: 2},
		{Name: "orders", Tier: 0, RoleRank: 6},
	}
	appSortServices(list)
	want := []string{"shop", "api", "postgres", "nginx", "orders", "zz-tool"}
	for i, n := range want {
		if list[i].Name != n {
			t.Fatalf("position %d: got %s, order %v", i, list[i].Name, list)
		}
	}
}

func TestAppAttributor(t *testing.T) {
	insts := []appLiveInst{
		{ServiceID: 1, Name: "orders", Source: "discovered", AgentID: "a1", PID: 100},
		{ServiceID: 2, Name: "billing", Source: "otel", AgentID: "a1", PID: 200, ContainerID: "abcdef0123456789"},
		{ServiceID: 3, Name: "orders", Source: "discovered", AgentID: "a2", PID: 100},
	}
	a := newAppAttributor(insts)
	check := func(p store.RuntimePackage, want int64, ok bool) {
		t.Helper()
		got, found := a.service(p)
		if found != ok || got != want {
			t.Fatalf("%+v: got %d,%v want %d,%v", p, got, found, want, ok)
		}
	}
	check(store.RuntimePackage{AgentID: "a1", PID: 100}, 1, true)
	check(store.RuntimePackage{AgentID: "a2", PID: 100}, 3, true)                  // same pid, other host
	check(store.RuntimePackage{AgentID: "a1", Container: "abcdef012345"}, 2, true) // short container id
	check(store.RuntimePackage{AgentID: "a1", Service: "orders"}, 1, true)         // older rows without pid
	check(store.RuntimePackage{AgentID: "a1", Service: "billing"}, 0, false)       // OTel names are not discovered names
	check(store.RuntimePackage{AgentID: "a1", PID: 999, Exe: "/usr/bin/java"}, 0, false)
}

func TestAppPackageForService(t *testing.T) {
	pkgs := map[string]string{"nginx-core": "1.18.0", "postgresql-16": "16.2", "postgresql-client-16": "16.2", "redis-server": "7.0", "php8.2-fpm": "8.2.7"}
	cases := map[string]string{"nginx": "nginx-core", "postgres": "postgresql-16", "redis": "redis-server"}
	for svc, want := range cases {
		role := appServiceRole(svc, nil, nil, 0)
		if got, _ := appPackageForService(svc, role, pkgs); got != want {
			t.Errorf("%s: got %q want %q", svc, got, want)
		}
	}
	if !appNameMatches("redis", "redis-server") || appNameMatches("api", "apache2") {
		t.Fatal("name match")
	}
}

func TestAppRiskWeigh(t *testing.T) {
	st := appDefaultSettings()
	if appRiskWeigh(3, st) != 3 {
		t.Fatal("default must not change severity")
	}
	st.Exposure, st.Criticality = "internet", "critical"
	if appRiskWeigh(3, st) != 5 || appRiskWeigh(5, st) != 5 {
		t.Fatal("internet + critical raises two levels, capped at 5")
	}
	r := []appRisk{{Kind: "host_finding", Severity: "high"}, {Kind: "code_vuln", Severity: "critical"}, {Kind: "service_alert", Severity: "high"}}
	sortRisks(r)
	if r[0].Kind != "code_vuln" || r[1].Kind != "service_alert" {
		t.Fatalf("risk order: %+v", r)
	}
}

func TestPostureGaps(t *testing.T) {
	var g postureGaps
	for i := 0; i < 7; i++ {
		g.add("Default branch protection", "o/r"+string(rune('a'+i)), gapReason(errors.New("auth error 403: check token permissions")), "fix")
	}
	g.add("Organisation 2FA requirement", "o", "setting not visible", "fix")
	l := g.list()
	if len(l) != 2 || l[0].Count != 7 || len(l[0].Examples) != 5 || l[0].Reason != "access denied (403)" {
		t.Fatalf("gaps: %+v", l)
	}
}

func TestDeployedCommits(t *testing.T) {
	cases := []struct {
		link, url string
		ok        bool
	}{
		{"acme/orders", "https://github.com/acme/orders.git", true},
		{"acme/orders", "github.com:acme/orders.git", true},
		{"Acme/Orders", "https://github.com/acme/orders", true},
		{"acme/orders", "https://github.com/acme/orders-ui", false},
		{"acme/orders", "", true},
		{"org/proj/api", "https://dev.azure.com/org/proj/_git/api", true},
		{"grp/sub/app", "https://gitlab.example.com/grp/sub/app.git", true},
	}
	for _, c := range cases {
		if repoMatches(c.link, c.url) != c.ok {
			t.Errorf("repoMatches(%q, %q) want %v", c.link, c.url, c.ok)
		}
	}
	a := "1111111111111111111111111111111111111111"
	b := "2222222222222222222222222222222222222222"
	deps := appDeployments([]appLiveInst{
		{Host: "h1", VCSRevision: a, VCSSource: "oci"},
		{Host: "h2", VCSRevision: b, VCSSource: "oci"},
		{Host: "h3", VCSRevision: b, VCSSource: "oci"},
		{Host: "h4"}, // reports nothing
	})
	if len(deps) != 2 || deps[0].Revision != b || deps[0].Instances != 2 || len(deps[0].Hosts) != 2 || deps[0].Short != "222222222222" {
		t.Fatalf("deployments: %+v", deps)
	}
	if !fullRevision(a) || fullRevision("abc1234") {
		t.Fatal("full revision")
	}
}
