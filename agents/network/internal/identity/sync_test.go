package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// identity.go is shared by every agent; the Linux agent holds the original.
func TestCopyMatchesLinuxAgent(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "linux", "internal", "identity", "identity.go"))
	if err != nil {
		t.Skip("linux agent source not present:", err)
	}
	got, _ := os.ReadFile("identity.go")
	if !bytes.Equal(got, want) {
		t.Fatal("identity.go differs from agents/linux/internal/identity/identity.go; copy it over")
	}
}
