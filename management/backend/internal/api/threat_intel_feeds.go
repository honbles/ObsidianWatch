package api

// threat_intel_feeds.go - plain-text botnet C2 IP feeds.
//
//   feodo         abuse.ch Feodo Tracker blocklist (free, no key)
//   spamhaus_bcl  Spamhaus Botnet Controller List. The BCL is a Spamhaus
//                 subscription product with no public download: the customer
//                 receives a feed URL (plain text or CSV) and enters it as this
//                 source's key. We pull that URL; nothing is fetched without it.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// The aggressive list adds IPs that have been seen as C2 over the past year (the default list holds
// only servers online right now, usually a handful).
const feodoURL = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"

// The recommended list holds only currently-active C2 servers (confidence 90).
const feodoRecommendedURL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

// feedMaxBytes bounds a feed download (a BCL is ~2,000 lines).
const feedMaxBytes = 8 << 20

// parseIPFeed extracts IP addresses from a plain-text or CSV blocklist. Lines
// starting with # or ; are comments. The first field of a line is taken
// (comma, semicolon, tab or space separated); "ip:port" and "ip,port" are both
// reduced to the IP. Duplicates are dropped, and anything that is not an
// IP address (headers, notes) is ignored.
func parseIPFeed(r io.Reader) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(io.LimitReader(r, feedMaxBytes))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		f := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == '\t' || r == ' ' || r == '"' })
		if len(f) == 0 {
			continue
		}
		cand := f[0]
		if h, _, err := net.SplitHostPort(cand); err == nil {
			cand = h
		}
		ip := net.ParseIP(strings.Trim(cand, "[]"))
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			continue
		}
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func fetchFeed(ctx context.Context, rawURL string) ([]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("feed URL must be a valid https:// address")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ObsidianWatch-SIEM/1.0")
	cl := &http.Client{Timeout: 60 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feed download failed: %v", redactURLErr(err))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 401, 403:
		return nil, fmt.Errorf("feed refused access (%s): check the URL/token and that the subscription is active", resp.Status)
	default:
		return nil, fmt.Errorf("feed returned %s", resp.Status)
	}
	ips := parseIPFeed(resp.Body)
	if len(ips) == 0 {
		return nil, fmt.Errorf("feed contained no usable IP addresses")
	}
	return ips, nil
}

// redactURLErr keeps a tokenised feed URL out of logs and the UI.
func redactURLErr(err error) string {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err.Error()
	}
	return err.Error()
}

func (e *ThreatIntelEngine) syncIPFeed(ctx context.Context, source, rawURL, malware string, conf int) (int, error) {
	ips, err := fetchFeed(ctx, rawURL)
	if err != nil {
		return 0, err
	}
	exp := time.Now().Add(72 * time.Hour) // refreshed on every sync; a delisted IP ages out
	iocs := make([]store.IOCIndicator, 0, len(ips))
	for _, ip := range ips {
		iocs = append(iocs, store.IOCIndicator{Source: source, IOCType: "ip", Value: ip, Malware: malware,
			ThreatType: "botnet_cc", Confidence: conf, Severity: confidenceToSeverity(conf), Tags: "botnet,c2", ExpiresAt: &exp})
	}
	return e.db.UpsertIOCs(ctx, iocs)
}

func (e *ThreatIntelEngine) syncFeodo(ctx context.Context) (int, error) {
	// Aggressive list (1-year C2 history) at 65 first, then the recommended
	// (currently active) list at 90 so overlapping IPs end up at 90.
	n1, err := e.syncIPFeed(ctx, "feodo", feodoURL, "Feodo/Emotet/QakBot family C2 (historical)", 65)
	if err != nil {
		return n1, err
	}
	n2, err := e.syncIPFeed(ctx, "feodo", feodoRecommendedURL, "Feodo/Emotet/QakBot family C2", 90)
	return n1 + n2, err
}

func (e *ThreatIntelEngine) syncSpamhausBCL(ctx context.Context, feedURL *string) (int, error) {
	if feedURL == nil || strings.TrimSpace(*feedURL) == "" {
		return 0, fmt.Errorf("Spamhaus BCL needs the feed URL from your Spamhaus subscription (enter it as the key); the list has no public download")
	}
	return e.syncIPFeed(ctx, "spamhaus_bcl", strings.TrimSpace(*feedURL), "Spamhaus BCL botnet controller", 95)
}
