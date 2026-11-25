package api

import (
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestInventoryRowsAndKeys(t *testing.T) {
	ev := store.Event{AgentID: "a1", Host: "web-1", Time: time.Unix(1700000000, 0), Raw: []byte(`{"inventory":{"service":"shop","container":"c1","exe":"/usr/bin/java",
		"packages":[{"e":"Maven","n":"org.apache.logging.log4j:log4j-core","v":"2.14.1","ev":"loaded"},
		            {"e":"Go","n":"golang.org/x/net","v":"v0.17.0","ev":"loaded"},
		            {"e":"PyPI","n":"PyYAML","v":"6.0","ev":"weird"},
		            {"e":"npm","n":"","v":"1"}]}}`)}
	rows := inventoryRows(ev)
	if len(rows) != 3 || rows[0].Service != "shop" || rows[0].Host != "web-1" || rows[1].Version != "0.17.0" || rows[2].Evidence != "deployed" {
		t.Fatalf("rows: %+v", rows)
	}
	if store.PackageNameKey("PyPI", "Py_YAML.x") != "py-yaml-x" || store.PackageNameKey("npm", "Lodash") != "lodash" {
		t.Fatal("name keys")
	}
	if trivyEcosystem("gomod") != "Go" || trivyEcosystem("pom") != "Maven" || trivyEcosystem("pnpm") != "npm" {
		t.Fatal("trivy ecosystems")
	}
}

func TestLabelWithoutCoverage(t *testing.T) {
	l := &reachLabeller{coverage: 0, cache: map[string]*findingReach{}}
	if r := l.label(nil, SASTFinding{RuleID: "SCA-CVE-1", Package: "x", Version: "1"}); r == nil || r.Level != "unknown" {
		t.Fatalf("no inventory anywhere must be unknown: %+v", r)
	}
	if l.label(nil, SASTFinding{RuleID: "SAST-1", Package: "x", Version: "1"}) != nil {
		t.Fatal("only dependency findings are labelled")
	}
}
