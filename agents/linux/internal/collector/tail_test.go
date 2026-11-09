//go:build linux

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLines(t *testing.T, n int) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "log")
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "line-%07d %s\n", i, strings.Repeat("x", 90))
	}
	if err := os.WriteFile(p, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestTailFileSmall(t *testing.T) {
	got := tailFile(writeLines(t, 250), 100)
	if len(got) != 100 || !strings.HasPrefix(got[0], "line-0000151") || !strings.HasPrefix(got[99], "line-0000250") {
		t.Fatalf("got %d lines, first=%q", len(got), got[0])
	}
}

func TestTailFileLargeOnlyReadsWindow(t *testing.T) {
	// ~110 bytes/line * 40000 = 4.4 MB, larger than tailWindow.
	got := tailFile(writeLines(t, 40000), 100)
	if len(got) != 100 || !strings.HasPrefix(got[99], "line-0040000") || !strings.HasPrefix(got[0], "line-0039901") {
		t.Fatalf("got %d lines, first=%q last=%q", len(got), got[0], got[len(got)-1])
	}
	for _, l := range got {
		if !strings.HasPrefix(l, "line-") {
			t.Fatalf("partial line leaked: %q", l)
		}
	}
}
