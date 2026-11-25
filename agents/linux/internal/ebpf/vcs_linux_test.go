package ebpf

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"obsidianwatch/linux-agent/internal/otel"
)

func TestFindGitCheckout(t *testing.T) {
	root := t.TempDir()
	gd := filepath.Join(root, "app", ".git")
	must := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sha := "0123456789abcdef0123456789abcdef01234567"
	must(filepath.Join(gd, "HEAD"), "ref: refs/heads/main\n")
	must(filepath.Join(gd, "packed-refs"), "# pack-refs\n"+sha+" refs/heads/main\n")
	must(filepath.Join(gd, "config"), "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://bot:ghp_secret@github.com/acme/orders.git\n")
	sub := filepath.Join(root, "app", "bin")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	v, ok := findGit(sub)
	if !ok || v.Revision != sha || v.Branch != "main" || v.Repo != "https://github.com/acme/orders.git" || v.Source != "git" {
		t.Fatalf("got %+v %v", v, ok)
	}
	// detached HEAD
	must(filepath.Join(gd, "HEAD"), sha+"\n")
	if v, _ := findGit(sub); v.Revision != sha || v.Branch != "" {
		t.Fatalf("detached: %+v", v)
	}
	// image labels win
	c := newVCSCache()
	got := c.lookup(root, 1, time.Unix(1, 0), "", ContainerInfo{Revision: "ABCDEF1234567", Source: "https://github.com/acme/web"})
	if got.Revision != "abcdef1234567" || got.Source != "oci" || got.Repo != "https://github.com/acme/web" {
		t.Fatalf("oci: %+v", got)
	}
	if otel.CleanRepoURL("git@github.com:acme/x.git") != "github.com:acme/x.git" || otel.CleanRevision("main") != "" {
		t.Fatal("clean")
	}
}
