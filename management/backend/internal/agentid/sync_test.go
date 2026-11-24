package agentid

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The ingest backend owns the original (backend/pkg/agentid). Both servers
// must parse identities the same way, so the copy must not drift.
func TestCopyMatchesBackend(t *testing.T) {
	orig := filepath.Join("..", "..", "..", "..", "backend", "pkg", "agentid", "agentid.go")
	want, err := os.ReadFile(orig)
	if err != nil {
		t.Skip("backend source not present:", err)
	}
	got, err := os.ReadFile("agentid.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("management/backend/internal/agentid/agentid.go differs from backend/pkg/agentid/agentid.go; copy it over")
	}
}
