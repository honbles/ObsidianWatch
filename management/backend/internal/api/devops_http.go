package api

// devops_http.go - the HTTP client every DevOps provider call goes through.
//
// validateDevOpsBaseURL only sees the hostname the user typed. A name such as
// 127.0.0.1.nip.io, or a DNS record the attacker changes after validation,
// still resolves to loopback or the cloud metadata address, and the connector
// token would be sent there. The check therefore runs again on the address
// actually dialled, after DNS resolution and on every redirect hop.

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"syscall"
	"time"

	"obsidianwatch/management/internal/telemetry"
)

// devopsAddrAllowed applies the same rules as validateDevOpsBaseURL to a
// resolved address.
func devopsAddrAllowed(a netip.Addr) error {
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
		return fmt.Errorf("devops: refusing to connect to %s", a)
	}
	if a.IsPrivate() && os.Getenv("OW_ALLOW_PRIVATE_DEVOPS") != "true" {
		return fmt.Errorf("devops: %s is a private address (set OW_ALLOW_PRIVATE_DEVOPS=true for self-hosted)", a)
	}
	return nil
}

func devopsDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	return devopsAddrAllowed(a)
}

var devopsHTTP = newDevOpsHTTPClient()

func newDevOpsHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: devopsDialControl}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Behind an outbound proxy the dial goes to the proxy, not the provider,
	// so the address check cannot apply there; the hostname check in
	// validateDevOpsBaseURL still does.
	if os.Getenv("HTTPS_PROXY") == "" && os.Getenv("https_proxy") == "" {
		tr.DialContext = dialer.DialContext
	}
	return &http.Client{
		Transport: telemetry.Transport(tr),
		Timeout:   60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("devops: too many redirects")
			}
			// Never over plain http. A cross-host redirect (GitHub tarballs go
			// to codeload.github.com) is followed without credentials: Go drops
			// Authorization itself, GitLab's PRIVATE-TOKEN has to be removed
			// here. The dial guard still checks the new host's address.
			if req.URL.Scheme != "https" {
				return http.ErrUseLastResponse
			}
			if req.URL.Host != via[0].URL.Host {
				req.Header.Del("Authorization")
				req.Header.Del("PRIVATE-TOKEN")
			}
			return nil
		},
	}
}

// maxWebhookBody is the largest webhook payload read before the signature check (DO-01: unauthenticated input
// stays small).
const maxWebhookBody = 1 << 20

// readWebhookBody reads a webhook payload. A body over the limit is refused with 413 and logged as such: it used
// to be cut off silently, fail its signature check and be logged as "invalid signature", which looked like an
// attack and hid the real cause (a large push).
func readWebhookBody(w http.ResponseWriter, r *http.Request, logger *slog.Logger, connector string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return nil, err
	}
	if len(body) > maxWebhookBody {
		logger.Warn("devops webhook: payload over the size limit, not processed", "connector", connector, "limit_bytes", maxWebhookBody)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return nil, errWebhookTooLarge
	}
	return body, nil
}

var errWebhookTooLarge = errors.New("webhook payload too large")
