package api

import "testing"

func TestParseResizeFrame(t *testing.T) {
	if c, r, ok := parseResizeFrame([]byte(`{"type":"resize","cols":100,"rows":40}`)); !ok || c != 100 || r != 40 {
		t.Fatal("valid frame rejected")
	}
	for _, bad := range []string{`{"type":"data","cols":100,"rows":40}`, `{"type":"resize","cols":5,"rows":40}`,
		`{"type":"resize","cols":100,"rows":900}`, `nope`, `ls -la`} {
		if _, _, ok := parseResizeFrame([]byte(bad)); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
