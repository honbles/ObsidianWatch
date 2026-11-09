package api

import "testing"

func TestCleanHostMeta(t *testing.T) {
	c, tags, msg := cleanHostMeta(" CRITICAL ", []string{"Prod", "prod", "pci:cde", ""})
	if msg != "" || c != "critical" || len(tags) != 2 || tags[0] != "prod" {
		t.Fatalf("%q %v %q", c, tags, msg)
	}
	if _, _, m := cleanHostMeta("urgent", nil); m == "" {
		t.Fatal("bad criticality accepted")
	}
	if _, _, m := cleanHostMeta("", []string{"bad tag!"}); m == "" {
		t.Fatal("bad tag accepted")
	}
	if c, _, _ := cleanHostMeta("", nil); c != "normal" {
		t.Fatal("default should be normal")
	}
}
