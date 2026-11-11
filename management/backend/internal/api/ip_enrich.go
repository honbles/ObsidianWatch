package api

// AbuseIPDB enrichment: GET /api/v1/enrich/ip/{ip} returns the abuse score
// for a public IP. Results are cached for 24h and lookups are capped per day
// so the free tier (1000 checks/day) is never exhausted by page views.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	abuseIPDBBase     = "https://api.abuseipdb.com/api/v2/check"
	abuseCacheTTL     = 24 * time.Hour
	abuseDailyBudget  = 900
	abuseMaxCacheSize = 5000
)

type IPReputation struct {
	IP           string `json:"ip"`
	AbuseScore   int    `json:"abuse_score"`
	TotalReports int    `json:"total_reports"`
	CountryCode  string `json:"country_code,omitempty"`
	ISP          string `json:"isp,omitempty"`
	Domain       string `json:"domain,omitempty"`
	UsageType    string `json:"usage_type,omitempty"`
	IsTor        bool   `json:"is_tor"`
	LastReported string `json:"last_reported,omitempty"`
	Cached       bool   `json:"cached"`
	Source       string `json:"source"`
}

type ipEnricher struct {
	mu      sync.Mutex
	cache   map[string]cachedRep
	day     string
	used    int
	baseURL string
	client  *http.Client
	now     func() time.Time
}

type cachedRep struct {
	rep IPReputation
	at  time.Time
}

func newIPEnricher() *ipEnricher {
	return &ipEnricher{
		cache:   map[string]cachedRep{},
		baseURL: abuseIPDBBase,
		client:  &http.Client{Timeout: 8 * time.Second},
		now:     time.Now,
	}
}

var errEnrichBudget = fmt.Errorf("daily AbuseIPDB lookup budget used up")

func (e *ipEnricher) lookup(ctx context.Context, apiKey, ip string) (*IPReputation, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() || parsed.IsMulticast() {
		return nil, fmt.Errorf("private or non-routable address; nothing to look up")
	}
	ip = parsed.String()

	e.mu.Lock()
	if c, ok := e.cache[ip]; ok && e.now().Sub(c.at) < abuseCacheTTL {
		r := c.rep
		r.Cached = true
		e.mu.Unlock()
		return &r, nil
	}
	today := e.now().UTC().Format("2006-01-02")
	if e.day != today {
		e.day, e.used = today, 0
	}
	if e.used >= abuseDailyBudget {
		e.mu.Unlock()
		return nil, errEnrichBudget
	}
	e.used++
	e.mu.Unlock()

	q := url.Values{"ipAddress": {ip}, "maxAgeInDays": {"90"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("abuseipdb rejected the API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb returned status %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Score        int    `json:"abuseConfidenceScore"`
			TotalReports int    `json:"totalReports"`
			Country      string `json:"countryCode"`
			ISP          string `json:"isp"`
			Domain       string `json:"domain"`
			UsageType    string `json:"usageType"`
			IsTor        bool   `json:"isTor"`
			LastReported string `json:"lastReportedAt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("unreadable abuseipdb response")
	}
	d := body.Data
	rep := IPReputation{IP: ip, AbuseScore: d.Score, TotalReports: d.TotalReports, CountryCode: d.Country,
		ISP: d.ISP, Domain: d.Domain, UsageType: d.UsageType, IsTor: d.IsTor, LastReported: d.LastReported, Source: "abuseipdb"}

	e.mu.Lock()
	if len(e.cache) >= abuseMaxCacheSize {
		e.cache = map[string]cachedRep{}
	}
	e.cache[ip] = cachedRep{rep: rep, at: e.now()}
	e.mu.Unlock()
	return &rep, nil
}

func handleEnrichIP(db *store.DB, en *ipEnricher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, _ := db.GetSetting(r.Context(), "ti.abuseipdb_api_key")
		if strings.TrimSpace(key) == "" {
			writeJSONError(w, http.StatusPreconditionFailed, "AbuseIPDB API key is not configured (Settings → Integrations)")
			return
		}
		rep, err := en.lookup(r.Context(), strings.TrimSpace(key), r.PathValue("ip"))
		switch {
		case err == errEnrichBudget:
			writeJSONError(w, http.StatusTooManyRequests, err.Error())
		case err != nil:
			writeJSONError(w, http.StatusBadRequest, err.Error())
		default:
			writeJSON(w, http.StatusOK, rep)
		}
	}
}
