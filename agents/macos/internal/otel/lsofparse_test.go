package otel

import "testing"

func TestLsofOwner(t *testing.T) {
	out := "p100\nn127.0.0.1:4318->127.0.0.1:55000\np4242\nn127.0.0.1:55000->127.0.0.1:4318\np5\nn*:80\n"
	if got := lsofOwner(out, "127.0.0.1:55000", "127.0.0.1:4318"); got != 4242 {
		t.Fatalf("got %d, want 4242 (the server end owned by pid 100 must be ignored)", got)
	}
	if lsofOwner(out, "127.0.0.1:1", "127.0.0.1:4318") != 0 || lsofOwner("", "a", "b") != 0 {
		t.Fatal("no match must give 0")
	}
}
