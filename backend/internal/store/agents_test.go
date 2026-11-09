package store

import "testing"

// The ingest and management services must hash install keys identically
// (SHA-256 hex), otherwise key verification silently fails across services.
func TestHashIngestKeyMatchesManagement(t *testing.T) {
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if hashIngestKey("abc") != abc {
		t.Fatalf("got %s", hashIngestKey("abc"))
	}
	if hashIngestKey("") != "" {
		t.Fatal("empty key must stay empty")
	}
}
