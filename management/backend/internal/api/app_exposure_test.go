package api

import "testing"

func TestInferExposure(t *testing.T) {
	cases := []struct {
		ips  []string
		want string
	}{
		{nil, "unknown"},
		{[]string{"", "127.0.0.1"}, "unknown"},
		{[]string{"10.0.0.5", "192.168.1.9"}, "internal"},
		{[]string{"10.0.0.5", "203.0.113.7"}, "internet"},
		{[]string{"198.51.100.0/24"}, "internet"},
		{[]string{"169.254.1.1", "fe80::1"}, "unknown"},
		{[]string{"not-an-ip"}, "unknown"},
	}
	for _, c := range cases {
		if got := appInferExposureFromIPs(c.ips); got.Exposure != c.want || got.Reason == "" {
			t.Errorf("%v: %+v want %s", c.ips, got, c.want)
		}
	}
	s := appDefaultSettings()
	s.ExposureInferred = "internet"
	if s.EffectiveExposure() != "internet" {
		t.Fatal("inferred value is used while the setting is unknown")
	}
	s.Exposure = "internal"
	if s.EffectiveExposure() != "internal" {
		t.Fatal("the analyst's setting wins")
	}
}
