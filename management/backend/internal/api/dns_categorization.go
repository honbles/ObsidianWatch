package api

// dns_categorization.go — DNS-based web content categorization.
//
// Three free, no-key-required sources:
//
// 1. Quad9 (9.9.9.9) — resolves domain. NXDOMAIN = blocked (malicious/phishing).
//    Blocks ~150k malicious domains. No false positives on legitimate sites.
//
// 2. SURBL (multi.surbl.org) — DNS blocklist covering spam, phishing, malware, abuse.
//    Returns 127.0.0.x where bit flags in last octet indicate categories:
//      bit 1  (1)  = SpamCop
//      bit 2  (2)  = SURBL (spam)
//      bit 3  (4)  = phish
//      bit 4  (8)  = malware
//      bit 5  (16) = abuse
//      bit 6  (32) = Botnet C&C
//      bit 7  (64) = phishing (JWSPAM)
//    NXDOMAIN = clean.
//
// 3. Spamhaus DBL (dbl.spamhaus.org) — domain blocklist.
//    Returns 127.0.1.x:
//      127.0.1.2  = spam domain
//      127.0.1.4  = phishing domain
//      127.0.1.5  = malware domain
//      127.0.1.6  = botnet C&C domain
//      127.0.1.102 = abused legit spam
//      127.0.1.103 = abused legit phish
//      127.0.1.104 = abused legit malware
//      127.0.1.105 = abused legit botnet
//    NXDOMAIN = clean.
//
// Categories stored in ioc_indicators.tags field.
// Results cached for 24h to avoid re-querying the same domain.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// DomainCategory represents a categorized domain.
type DomainCategory struct {
	Domain     string
	Categories []string // e.g. ["malware", "botnet_cc", "phishing"]
	Blocked    bool     // true if Quad9 blocks it
	Source     string   // "quad9", "surbl", "spamhaus_dbl"
	Severity   int
}

// CategorizeDomain checks a domain against free DNS blocklists.
// Results are cached in ioc_indicators for 24h.
func CategorizeDomain(ctx context.Context, domain string, db *store.DB) (*DomainCategory, error) {
	if domain == "" || !strings.Contains(domain, ".") {
		return nil, nil
	}

	// Skip IPs and internal domains
	if net.ParseIP(domain) != nil {
		return nil, nil
	}
	if isInternalDomain(domain) {
		return nil, nil
	}

	// Check cache first — ioc_type="domain_category"
	existing, err := db.GetIOCByTypeAndValue(ctx, "domain_category", strings.ToLower(domain))
	if err == nil && existing != nil {
		// Cache hit
		return iocToDomainCategory(existing), nil
	}

	result := &DomainCategory{Domain: domain}

	// Check 1: Quad9 — NXDOMAIN = blocked malicious
	if blocked, _ := checkQuad9(ctx, domain); blocked {
		result.Blocked = true
		result.Categories = append(result.Categories, "malicious")
		result.Source = "quad9"
		result.Severity = 4
	}

	// Check 2: SURBL
	if cats, sev := checkSURBL(ctx, domain); len(cats) > 0 {
		result.Categories = append(result.Categories, cats...)
		if sev > result.Severity {
			result.Severity = sev
		}
		if result.Source == "" {
			result.Source = "surbl"
		} else {
			result.Source += "+surbl"
		}
	}

	// Check 3: Spamhaus DBL
	if cats, sev := checkSpamhausDBL(ctx, domain); len(cats) > 0 {
		result.Categories = append(result.Categories, cats...)
		if sev > result.Severity {
			result.Severity = sev
		}
		if result.Source == "" {
			result.Source = "spamhaus_dbl"
		} else {
			result.Source += "+spamhaus_dbl"
		}
	}

	if len(result.Categories) == 0 && !result.Blocked {
		// Clean — cache the clean result too to avoid repeated lookups
		db.StoreIOC(ctx, store.IOCIndicator{
			Source:     "dns_cat",
			IOCType:    "domain_category",
			Value:      strings.ToLower(domain),
			ThreatType: "clean",
			Confidence: 90,
			Severity:   1,
			Tags:       "clean",
			ExpiresAt:  timePtr(time.Now().Add(24 * time.Hour)),
		})
		return nil, nil
	}

	// Cache the result
	tags := strings.Join(result.Categories, ",")
	db.StoreIOC(ctx, store.IOCIndicator{
		Source:     "dns_cat",
		IOCType:    "domain_category",
		Value:      strings.ToLower(domain),
		ThreatType: strings.Join(result.Categories, "|"),
		Confidence: 85,
		Severity:   result.Severity,
		Tags:       tags,
		ExpiresAt:  timePtr(time.Now().Add(24 * time.Hour)),
	})

	return result, nil
}

func iocToDomainCategory(ioc *store.IOCIndicator) *DomainCategory {
	if ioc.Tags == "clean" || ioc.ThreatType == "clean" {
		return nil
	}
	cats := strings.Split(ioc.Tags, ",")
	return &DomainCategory{
		Domain:     ioc.Value,
		Categories: cats,
		Blocked:    strings.Contains(ioc.ThreatType, "malicious"),
		Source:     ioc.Source,
		Severity:   ioc.Severity,
	}
}

// checkQuad9 resolves a domain via Quad9 (9.9.9.9).
// Returns true if Quad9 blocks it (NXDOMAIN when it shouldn't be).
func checkQuad9(ctx context.Context, domain string) (bool, error) {
	// First verify Quad9 is reachable — if not, skip check entirely
	// (avoids false positives when Quad9 is blocked by firewall/proxy)
	conn, testErr := net.DialTimeout("udp", "9.9.9.9:53", 2*time.Second)
	if testErr != nil {
		// Quad9 unreachable — cannot determine block status
		return false, nil
	}
	conn.Close()

	// Resolve via system resolver first
	systemIPs, sysErr := net.DefaultResolver.LookupHost(ctx, domain)

	// Resolve via Quad9
	quad9Resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "9.9.9.9:53")
		},
	}
	quad9IPs, quad9Err := quad9Resolver.LookupHost(ctx, domain)

	// Quad9 blocks = system resolves but Quad9 returns NXDOMAIN
	if sysErr == nil && len(systemIPs) > 0 && (quad9Err != nil || len(quad9IPs) == 0) {
		return true, nil
	}
	return false, nil
}

// checkSURBL queries the SURBL DNS blocklist.
// Returns categories and severity.
func checkSURBL(ctx context.Context, domain string) ([]string, int) {
	// Use registrable domain (strip subdomains)
	rd := registrableDomain(domain)
	if rd == "" {
		return nil, 0
	}

	// SURBL lookup: <domain>.multi.surbl.org
	lookup := rd + ".multi.surbl.org"
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", dnsblResolverAddr())
		},
	}

	ips, err := resolver.LookupHost(ctx, lookup)
	if err != nil || len(ips) == 0 {
		return nil, 0 // NXDOMAIN = clean
	}

	// Parse the return code
	var cats []string
	maxSev := 0
	for _, ip := range ips {
		parts := strings.Split(ip, ".")
		// F-19: only 127.0.0.x are category codes. Anything else under 127/8
		// (notably 127.255.255.x) is an error/refusal answer (e.g. query via
		// a public resolver) and must not be read as a bit field.
		if len(parts) != 4 || parts[0] != "127" || parts[1] != "0" || parts[2] != "0" {
			continue
		}
		// Parse last octet as bit flags
		var bits int
		fmt.Sscanf(parts[3], "%d", &bits)
		if bits&2 != 0 { cats = append(cats, "spam"); if 2 > maxSev { maxSev = 2 } }
		if bits&4 != 0 { cats = append(cats, "phishing"); if 4 > maxSev { maxSev = 4 } }
		if bits&8 != 0 { cats = append(cats, "malware"); if 5 > maxSev { maxSev = 5 } }
		if bits&16 != 0 { cats = append(cats, "abuse"); if 3 > maxSev { maxSev = 3 } }
		if bits&32 != 0 { cats = append(cats, "botnet_cc"); if 5 > maxSev { maxSev = 5 } }
		if bits&64 != 0 { cats = append(cats, "phishing"); if 4 > maxSev { maxSev = 4 } }
	}
	return cats, maxSev
}

// checkSpamhausDBL queries the Spamhaus Domain Block List.
func checkSpamhausDBL(ctx context.Context, domain string) ([]string, int) {
	rd := registrableDomain(domain)
	if rd == "" {
		return nil, 0
	}

	lookup := rd + ".dbl.spamhaus.org"
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", dnsblResolverAddr())
		},
	}

	ips, err := resolver.LookupHost(ctx, lookup)
	if err != nil || len(ips) == 0 {
		return nil, 0
	}

	var cats []string
	maxSev := 0
	for _, ip := range ips {
		if strings.HasPrefix(ip, "127.255.255.") {
			continue // Spamhaus error/refusal codes, not a listing
		}
		switch ip {
		case "127.0.1.2": cats = append(cats, "spam"); if 2 > maxSev { maxSev = 2 }
		case "127.0.1.4": cats = append(cats, "phishing"); if 4 > maxSev { maxSev = 4 }
		case "127.0.1.5": cats = append(cats, "malware"); if 5 > maxSev { maxSev = 5 }
		case "127.0.1.6": cats = append(cats, "botnet_cc"); if 5 > maxSev { maxSev = 5 }
		case "127.0.1.102": cats = append(cats, "spam"); if 2 > maxSev { maxSev = 2 }
		case "127.0.1.103": cats = append(cats, "phishing"); if 4 > maxSev { maxSev = 4 }
		case "127.0.1.104": cats = append(cats, "malware"); if 5 > maxSev { maxSev = 5 }
		case "127.0.1.105": cats = append(cats, "botnet_cc"); if 5 > maxSev { maxSev = 5 }
		}
	}
	return cats, maxSev
}

// registrableDomain strips subdomains, returning "example.com" from "sub.example.com".
// Simplified: takes the last two labels. Not perfect for .co.uk etc but good enough.
func registrableDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	// For known two-part TLDs
	twoPartTLDs := map[string]bool{
		"co.uk": true, "co.nz": true, "co.za": true, "co.jp": true,
		"com.au": true, "org.uk": true, "net.uk": true, "gov.uk": true,
	}
	if len(parts) >= 3 {
		candidate := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if twoPartTLDs[candidate] && len(parts) >= 3 {
			return parts[len(parts)-3] + "." + candidate
		}
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// ── Background domain categorization worker ───────────────────────────────────

// DomainCategorizationWorker processes DNS events and categorizes new domains.
type DomainCategorizationWorker struct {
	db     *store.DB
	logger *slog.Logger
}

func NewDomainCategorizationWorker(db *store.DB, logger *slog.Logger) *DomainCategorizationWorker {
	return &DomainCategorizationWorker{db: db, logger: logger}
}

func (w *DomainCategorizationWorker) Run(ctx context.Context) {
	w.logger.Info("dns-cat: domain categorization worker started")

	// Run every 10 minutes — process new DNS events seen since last run
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	// Initial run
	w.categorizeRecentDomains(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.categorizeRecentDomains(ctx)
		}
	}
}

func (w *DomainCategorizationWorker) categorizeRecentDomains(ctx context.Context) {
	// Get unique domains from DNS events in the last 24h not yet categorized
	rows, err := w.db.QueryContext(ctx, `
		SELECT DISTINCT dst_ip FROM events
		WHERE event_type = 'dns'
		  AND dst_ip IS NOT NULL
		  AND dst_ip NOT LIKE '%:%'
		  AND time > NOW() - INTERVAL '24 hours'
		  AND dst_ip NOT IN (
		    SELECT value FROM ioc_indicators
		    WHERE ioc_type = 'domain_category'
		      AND (expires_at IS NULL OR expires_at > NOW())
		  )
		LIMIT 200`)
	if err != nil {
		return
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err == nil && d != "" {
			domains = append(domains, d)
		}
	}
	rows.Close()

	if len(domains) == 0 {
		return
	}

	w.logger.Info("dns-cat: categorizing domains", "count", len(domains))

	for _, domain := range domains {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cat, err := CategorizeDomain(ctx, domain, w.db)
		if err != nil {
			continue
		}
		if cat != nil {
			w.logger.Info("dns-cat: flagged domain",
				"domain", domain,
				"categories", cat.Categories,
				"severity", cat.Severity)
		}

		// Rate limit — be a good citizen with free DNS services
		time.Sleep(200 * time.Millisecond)
	}
}

// internalSuffixes are never sent to third-party blocklists (F-19): they
// would leak internal hostnames and can never be listed anyway.
var internalSuffixes = []string{
	".local", ".internal", ".lan", ".home", ".corp", ".intranet", ".localdomain",
	".home.arpa", ".test", ".invalid", ".localhost", ".in-addr.arpa", ".ip6.arpa",
	".compute.internal", ".svc.cluster.local",
}

func isInternalDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if !strings.Contains(d, ".") {
		return true // single-label names are always internal
	}
	for _, suf := range internalSuffixes {
		if strings.HasSuffix(d, suf) {
			return true
		}
	}
	return false
}

// dnsblResolverAddr is the resolver used for DNSBL queries. Spamhaus and
// SURBL refuse queries relayed through big public resolvers, so deployments
// should point this at their own recursive resolver (OW_DNSBL_RESOLVER=host:53).
func dnsblResolverAddr() string {
	if v := strings.TrimSpace(os.Getenv("OW_DNSBL_RESOLVER")); v != "" {
		return v
	}
	return "8.8.8.8:53"
}
