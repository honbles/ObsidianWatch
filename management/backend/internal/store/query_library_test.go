package store

import (
	"encoding/json"
	"os"
	"testing"
)

// Every query in the Events page's query library must parse and compile. (Whether each one finds the events
// it is named after is TestQueryLibraryMatchesAgentEvents, which needs PostgreSQL.)
func TestEventsQueryLibraryParses(t *testing.T) {
	b, err := os.ReadFile("../../../frontend/src/pages/events/query-library.json")
	if err != nil {
		t.Skip("frontend not present:", err)
	}
	var lib []struct{ Group, Label, Q string }
	if err := json.Unmarshal(b, &lib); err != nil {
		t.Fatal(err)
	}
	for _, l := range lib {
		e, err := ParseEventQuery(l.Q)
		if err != nil {
			t.Errorf("%s / %s: %q: %v", l.Group, l.Label, l.Q, err)
			continue
		}
		if _, _, err := e.SQL(1); err != nil {
			t.Errorf("%s / %s: %q: %v", l.Group, l.Label, l.Q, err)
		}
	}
	if len(lib) < 150 {
		t.Fatalf("only %d library queries found", len(lib))
	}
}
