package otel

import (
	"testing"
	"time"
)

func TestBinderRules(t *testing.T) {
	b := NewBinder()
	t0 := time.Unix(1000, 0)
	app := Peer{Resolved: true, PID: 10, ProcStart: t0, Exe: "/opt/app/java"}
	if got := b.Bind("shop", "prod", app); got != IdentityVerified {
		t.Fatalf("first claimant binds: %s", got)
	}
	if got := b.Bind("shop", "prod", app); got != IdentityVerified {
		t.Fatalf("same process: %s", got)
	}
	worker := Peer{Resolved: true, PID: 11, ProcStart: t0, Exe: "/opt/app/java"}
	if got := b.Bind("shop", "prod", worker); got != IdentityVerified {
		t.Fatalf("same executable (worker/restart): %s", got)
	}
	evil := Peer{Resolved: true, PID: 666, ProcStart: t0, Exe: "/tmp/payload"}
	if got := b.Bind("shop", "prod", evil); got != IdentityAsserted {
		t.Fatalf("unrelated process claiming the service must be asserted: %s", got)
	}
	// An asserted claim must not enlarge the allowed set.
	if got := b.Bind("shop", "prod", evil); got != IdentityAsserted {
		t.Fatalf("still asserted: %s", got)
	}
	if got := b.Bind("shop", "prod", Peer{Reason: "unresolved"}); got != IdentityAsserted {
		t.Fatalf("unresolved: %s", got)
	}
	// Another service is independent; environment is part of identity.
	if got := b.Bind("shop", "staging", evil); got != IdentityVerified {
		t.Fatalf("different environment is its own service: %s", got)
	}
}

func TestHasherAndClientIP(t *testing.T) {
	h := NewHasher("org-key")
	a, b := h.Hash("alice@example.com"), h.Hash("alice@example.com")
	if a == "" || a != b || len(a) != 16 || a == h.Hash("bob@example.com") || contains(a, "alice") {
		t.Fatalf("hash: %q %q", a, b)
	}
	if NewHasher("other").Hash("alice@example.com") == a {
		t.Fatal("key must change the hash")
	}
	if nk := NewHasher(""); nk.Enabled() || nk.Hash("x") != "" {
		t.Fatal("no key → no identifiers")
	}
	for in, want := range map[string]string{"203.0.113.77": "203.0.113.0/24", "2001:db8:1:2:3:4:5:6": "2001:db8:1::/48"} {
		if got := ApplyClientIP(in, ClientIPTruncated); got != want {
			t.Fatalf("truncate %s = %s want %s", in, got, want)
		}
	}
	if ApplyClientIP("203.0.113.77", ClientIPOff) != "" || ApplyClientIP("203.0.113.77", ClientIPFull) != "203.0.113.77" || ApplyClientIP("junk", ClientIPTruncated) != "" {
		t.Fatal("ip modes")
	}
}
