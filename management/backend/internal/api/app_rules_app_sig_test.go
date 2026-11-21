package api

import "testing"

func TestAppInjectionExcAcceptsAgentSignatures(t *testing.T) {
	for _, s := range []string{"param.sql-injection", "param.path-traversal", "param.script-injection"} {
		if !appIsInjectionExc(s) {
			t.Errorf("%s should count as injection", s)
		}
	}
	if appIsInjectionExc("java.lang.NullPointerException") {
		t.Error("plain exception is not an injection")
	}
}
