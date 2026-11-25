package store

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// Every query in the Events page's query library must parse and compile.
func TestEventsQueryLibraryParses(t *testing.T) {
	b, err := os.ReadFile("../../../frontend/src/pages/Events.jsx")
	if err != nil {
		t.Skip("frontend not present:", err)
	}
	re := regexp.MustCompile(`field: 'kql', label: ("(?:[^"\\]|\\.)*")`)
	n := 0
	for _, m := range re.FindAllSubmatch(b, -1) {
		var q string
		if err := json.Unmarshal(m[1], &q); err != nil {
			t.Fatalf("bad literal %s", m[1])
		}
		n++
		e, err := ParseEventQuery(q)
		if err != nil {
			t.Errorf("%q: %v", q, err)
			continue
		}
		if _, _, err := e.SQL(1); err != nil {
			t.Errorf("%q: %v", q, err)
		}
	}
	if n < 100 {
		t.Fatalf("only %d library queries found", n)
	}
}
