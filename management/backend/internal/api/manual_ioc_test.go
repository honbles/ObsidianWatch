package api

import "testing"

func TestNormalizeManualIOC(t *testing.T) {
	ok := []struct{ typ, in, want string }{
		{"ip", " 203.0.113.7 ", "203.0.113.7"},
		{"domain", "Evil.Example.COM.", "evil.example.com"},
		{"hash", "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
		{"hash", "sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
	}
	for _, c := range ok {
		_, got, err := normalizeManualIOC(c.typ, c.in)
		if err != nil || got != c.want {
			t.Errorf("%s %q -> %q, %v", c.typ, c.in, got, err)
		}
	}
	for _, c := range [][2]string{{"ip", "999.1.1.1"}, {"domain", "not a domain"}, {"hash", "abc"}, {"hash", "zz" + "a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}, {"url", "http://x"}} {
		if _, _, err := normalizeManualIOC(c[0], c[1]); err == nil {
			t.Errorf("%v should be rejected", c)
		}
	}
}
