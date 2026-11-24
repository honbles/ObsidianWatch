//go:build linux

package collector

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDpkgIndexLookup(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "bin", "tool")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum([]byte("hello"))
	want := hex.EncodeToString(sum[:])
	info := filepath.Join(dir, "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		t.Fatal(err)
	}
	line := want + "  " + strings.TrimPrefix(file, "/") + "\n"
	if err := os.WriteFile(filepath.Join(info, "tool-pkg:amd64.md5sums"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := loadDpkgIndex(info)
	if err != nil || !idx.available {
		t.Fatalf("index: %v available=%v", err, idx != nil && idx.available)
	}
	e, ok := idx.lookup(file)
	if !ok || e.pkg != "tool-pkg" || e.md5 != want {
		t.Fatalf("lookup got %+v ok=%v", e, ok)
	}
	if _, ok := idx.lookup("/tmp/not-owned"); ok {
		t.Fatal("unowned path must not resolve")
	}
}

func TestDpkgIndexMissingDirIsUnknown(t *testing.T) {
	idx, _ := loadDpkgIndex(filepath.Join(t.TempDir(), "nope"))
	if idx == nil || idx.available {
		t.Fatal("missing dpkg dir must give an unavailable index")
	}
}

func TestPkgPathCandidates(t *testing.T) {
	got := pkgPathCandidates("/usr/bin/dash")
	if len(got) != 2 || got[1] != "/bin/dash" {
		t.Fatalf("got %v", got)
	}
}

func TestParseRPMDigests(t *testing.T) {
	out := "/usr/bin/dash\t" + strings.Repeat("AB", 32) + "\tdash\n/usr/share/doc/dash/README\t\tdash\nbad line\n"
	m := parseRPMDigests(out)
	if e, ok := m["/usr/bin/dash"]; !ok || e.pkg != "dash" || e.digest != strings.Repeat("ab", 32) {
		t.Fatalf("got %+v ok=%v", e, ok)
	}
	if len(m) != 2 {
		t.Fatalf("want 2 entries, got %d", len(m))
	}
}
