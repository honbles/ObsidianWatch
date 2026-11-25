package api

import (
	"context"
	"testing"
)

func TestSBOMViewFlatten(t *testing.T) {
	res, err := parseTrivy([]byte(trivySample), "acme/web", true)
	if err != nil {
		t.Fatal(err)
	}
	comps, err := buildSBOMView(context.Background(), nil, res.SBOM)
	if err != nil || len(comps) != 2 {
		t.Fatalf("%v %+v", err, comps)
	}
	by := map[string]sbomViewComponent{}
	for _, c := range comps {
		by[c.Name] = c
	}
	l := by["lodash"]
	if l.Ecosystem != "npm" || len(l.Vulns) != 1 || l.Vulns[0].ID != "CVE-2020-8203" || l.Vulns[0].Severity != "high" ||
		len(l.Licenses) != 1 || l.Licenses[0] != "MIT" || l.File != "package-lock.json" || l.Runtime != "unknown" {
		t.Fatalf("lodash: %+v", l)
	}
	if !by["left-pad"].Transitive || len(by["left-pad"].Vulns) != 0 {
		t.Fatalf("left-pad: %+v", by["left-pad"])
	}
	if ecosystemOfPURL("pkg:maven/org.apache/x@1") != "Maven" || ecosystemOfPURL("pkg:golang/github.com/a/b@v1") != "Go" {
		t.Fatal("purl ecosystems")
	}
}
