package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCorrelatorSnapshotRoundTrip(t *testing.T) {
	now := time.Now()
	a := newAuthCorrelator()
	q := newSeqCorrelator()
	a.byUser["s|bob"] = []time.Time{now.Add(-time.Minute), now.Add(-3 * time.Hour)}
	a.byIP["s|1.2.3.4"] = []authFailRec{{t: now.Add(-time.Minute), user: "bob"}}
	q.state["R|k"] = now.Add(-time.Minute)
	q.state["R|old"] = now.Add(-5 * time.Hour)
	var s correlatorSnapshot
	a.snapshotInto(&s)
	q.snapshotInto(&s)
	b, _ := json.Marshal(s)
	var s2 correlatorSnapshot
	if err := json.Unmarshal(b, &s2); err != nil {
		t.Fatal(err)
	}
	a2, q2 := newAuthCorrelator(), newSeqCorrelator()
	a2.restoreFrom(s2, now)
	q2.restoreFrom(s2, now)
	if len(a2.byUser["s|bob"]) != 1 || len(a2.byIP["s|1.2.3.4"]) != 1 {
		t.Fatalf("auth restore wrong: %+v %+v", a2.byUser, a2.byIP)
	}
	if _, ok := q2.state["R|k"]; !ok {
		t.Fatal("fresh seq state lost")
	}
	if _, ok := q2.state["R|old"]; ok {
		t.Fatal("stale seq state should be dropped")
	}
}
