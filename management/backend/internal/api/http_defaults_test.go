package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultClientHasTimeout(t *testing.T) {
	if http.DefaultClient.Timeout <= 0 || http.DefaultClient.Timeout > outboundTimeout {
		t.Fatalf("DefaultClient timeout = %v", http.DefaultClient.Timeout)
	}
}

func TestCappedBodyTransportTruncates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", 1000)))
	}))
	defer srv.Close()
	c := &http.Client{Transport: cappedBodyTransport{next: http.DefaultTransport, limit: 100}}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if len(b) != 100 {
		t.Fatalf("read %d bytes, want 100", len(b))
	}
	if _, ok := http.DefaultClient.Transport.(cappedBodyTransport); !ok {
		t.Fatal("DefaultClient transport not capped")
	}
}
