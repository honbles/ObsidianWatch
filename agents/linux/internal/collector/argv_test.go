//go:build linux

package collector

import (
	"strings"
	"testing"
)

func TestCapArgv(t *testing.T) {
	long := strings.Repeat("a", maxArgvBytes+50)
	many := make([]string, maxArgvItems+10)
	for i := range many {
		many[i] = "x"
	}
	if got := capArgv(many); len(got) != maxArgvItems {
		t.Errorf("items: %d", len(got))
	}
	if got := capArgv([]string{"bash", "-c", long}); len(got[2]) != maxArgvBytes || got[1] != "-c" {
		t.Errorf("bytes cap or order wrong: %v", got)
	}
}
