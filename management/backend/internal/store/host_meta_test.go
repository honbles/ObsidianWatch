package store

import "testing"

func TestWeightedSeverity(t *testing.T) {
	if WeightedSeverity(3, "critical") != 4 || WeightedSeverity(5, "critical") != 5 {
		t.Fatal("critical hosts raise severity, capped at 5")
	}
	for _, c := range []string{"low", "normal", "high", ""} {
		if WeightedSeverity(3, c) != 3 {
			t.Fatalf("%q must not change severity", c)
		}
	}
	if got := splitTags(" a, b,, c "); len(got) != 3 || got[2] != "c" {
		t.Fatalf("%v", got)
	}
}
