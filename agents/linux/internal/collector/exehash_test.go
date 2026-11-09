//go:build linux

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestExeSHA256OfSelf(t *testing.T) {
	got := exeSHA256(os.Getpid())
	if got == "" {
		t.Skip("test binary larger than exeHashMaxSize or /proc unavailable")
	}
	b, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash mismatch: %s", got)
	}
	if again := exeSHA256(os.Getpid()); again != got {
		t.Fatal("cached value differs")
	}
	if exeSHA256(0x7fffffff) != "" {
		t.Fatal("missing pid must give empty hash")
	}
}
