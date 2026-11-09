package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestExecPathFromProcArgs(t *testing.T) {
	buf := append([]byte{2, 0, 0, 0}, []byte("/usr/bin/ssh\x00\x00\x00ssh\x00host\x00")...)
	if got := execPathFromProcArgs(buf); got != "/usr/bin/ssh" {
		t.Fatalf("got %q", got)
	}
	if execPathFromProcArgs([]byte{1, 0}) != "" {
		t.Fatal("short buffer should give empty path")
	}
}

func TestHashFileCached(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bin")
	_ = os.WriteFile(p, []byte("hello"), 0o755)
	sum := sha256.Sum256([]byte("hello"))
	want := hex.EncodeToString(sum[:])
	if hashFileCached(p) != want || hashFileCached(p) != want {
		t.Fatal("hash mismatch")
	}
	if hashFileCached("/nonexistent/x") != "" || hashFileCached("") != "" {
		t.Fatal("missing file should give empty hash")
	}
}
