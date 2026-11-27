package api

import "testing"

func TestRepoRef(t *testing.T) {
	for in, want := range map[string][2]string{
		"https://github.com/Acme/Api.git":         {"github.com", "acme/api"},
		"git@github.com:acme/api.git":             {"github.com", "acme/api"},
		"github.com/acme/api":                     {"github.com", "acme/api"},
		"https://token@gitlab.example.com/g/s/r":  {"gitlab.example.com", "g/s/r"},
		"https://dev.azure.com/org/proj/_git/svc": {"dev.azure.com", "org/proj/_git/svc"},
		"": {"", ""},
	} {
		h, p := repoRef(in)
		if h != want[0] || p != want[1] {
			t.Errorf("%q: got %q %q", in, h, p)
		}
	}
	if !repoMatches("Acme/Api", "https://github.com/acme/api.git") || repoMatches("acme/api", "https://github.com/acme/api2") {
		t.Error("repoMatches")
	}
}
