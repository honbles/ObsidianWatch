package collector

import (
	"os"
	"testing"
)

func TestLinuxProcGUIDStableForSamePID(t *testing.T) {
	a := linuxProcGUID(os.Getpid())
	b := linuxProcGUID(os.Getpid())
	if a == "" || a != b {
		t.Fatalf("guid must be non-empty and stable for a live pid: %q %q", a, b)
	}
	if other := linuxProcGUID(1); other == a {
		t.Fatal("different processes must not share a guid")
	}
}
