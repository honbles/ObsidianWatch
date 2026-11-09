//go:build linux

package collector

import (
	"os"
	"testing"
)

func TestParsePasswdAndStatus(t *testing.T) {
	pw := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\nbroken\n"
	if parsePasswdName(pw, 1000) != "alice" || parsePasswdName(pw, 0) != "root" || parsePasswdName(pw, 5) != "" {
		t.Fatal("passwd parsing wrong")
	}
	ppid, uid, ok := parseProcStatus("Name:\tbash\nPPid:\t42\nUid:\t1000\t1000\t1000\t1000\n")
	if !ok || ppid != 42 || uid != 1000 {
		t.Fatalf("status parsing wrong: %d %d %v", ppid, uid, ok)
	}
	if _, _, ok := parseProcStatus("Name:\tx\n"); ok {
		t.Fatal("status without Uid must not be ok")
	}
}

func TestLookupWriterSelf(t *testing.T) {
	w := lookupWriter(os.Getpid())
	if w.Exe == "" || w.PPID <= 0 || w.User == "" {
		t.Fatalf("self lookup incomplete: %+v", w)
	}
	if (lookupWriter(0) != writerInfo{}) {
		t.Fatal("pid 0 must give empty info")
	}
}
