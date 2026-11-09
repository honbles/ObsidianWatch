package api

import "testing"

func TestBQCISControls(t *testing.T) {
	c := bqCISControls([]bqDatasetFacts{{ID: "a", Public: true, CMEK: true}, {ID: "b", CMEK: false}})
	if len(c) != 2 || c[0].Status != "FAIL" || c[1].Status != "FAIL" {
		t.Fatalf("%+v", c)
	}
	c = bqCISControls([]bqDatasetFacts{{ID: "a", CMEK: true}})
	if c[0].Status != "PASS" || c[1].Status != "PASS" {
		t.Fatalf("%+v", c)
	}
	if len(cisIAMControls()) == 0 || len(cisvmControls()) == 0 {
		t.Fatal("UNKNOWN placeholders must list the controls that could not be assessed")
	}
}
