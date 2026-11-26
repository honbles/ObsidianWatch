package store

import "testing"

func TestNormalizeSavedQuery(t *testing.T) {
	cases := map[string]string{
		"OS: windows Type: process powershell":   "os:windows type:process powershell",
		"Severity: 4 IP: 10.0.0.5 Port: 445":     "sev>=4 ip:10.0.0.5 port:445",
		"Type: cloud.* Source: cloudtrail":       "type:cloud.* source:cloudtrail",
		"type:process proc:(powershell or pwsh)": "type:process proc:(powershell or pwsh)",
		`cmd:"sc create" Proto: tcp`:             `cmd:"sc create" proto:tcp`,
	}
	for in, want := range cases {
		got := NormalizeSavedQuery(in)
		if got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
		if _, err := ParseEventQuery(got); err != nil {
			t.Errorf("%q does not parse: %v", got, err)
		}
	}
}
