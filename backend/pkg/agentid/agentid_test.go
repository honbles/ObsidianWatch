package agentid

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"
)

func TestFromCert(t *testing.T) {
	id := New()
	other := New()
	u := func(s string) *url.URL { x, _ := url.Parse(s); return x }
	cases := []struct {
		name string
		c    x509.Certificate
		ok   bool
	}{
		{"good", x509.Certificate{Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{URI(id)}}, true},
		{"no SAN", x509.Certificate{Subject: pkix.Name{CommonName: id}}, false},
		{"CN differs", x509.Certificate{Subject: pkix.Name{CommonName: other}, URIs: []*url.URL{URI(id)}}, false},
		{"two ids", x509.Certificate{Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{URI(id), URI(other)}}, false},
		{"hostname id", x509.Certificate{Subject: pkix.Name{CommonName: "web-01"}, URIs: []*url.URL{u(URIPrefix + "web-01")}}, false},
	}
	for _, c := range cases {
		got, err := FromCert(&c.c)
		if (err == nil) != c.ok || (c.ok && got != id) {
			t.Errorf("%s: got %q, %v", c.name, got, err)
		}
	}
	if New() == New() || !Valid(id) || Valid("ag-XYZ") {
		t.Error("New/Valid")
	}
}
