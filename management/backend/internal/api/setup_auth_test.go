package api

import "testing"

func TestValidHTTPURL(t *testing.T) {
	cases := []struct {
		u     string
		https bool
		want  bool
	}{
		{"https://a.example:8443", true, true},
		{"http://a.example", true, false},
		{"http://10.0.0.1", false, true},
		{"javascript:alert(1)", false, false},
		{"file:///etc/passwd", false, false},
		{"https://", true, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := validHTTPURL(c.u, c.https); got != c.want {
			t.Errorf("validHTTPURL(%q,%v)=%v want %v", c.u, c.https, got, c.want)
		}
	}
}
