package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/auth"
)

var ispCache = struct {
	sync.RWMutex
	data map[string]map[string]string
}{data: make(map[string]map[string]string)}

// ispHTTPClient has a hard timeout so a slow provider can't pin goroutines.
var ispHTTPClient = &http.Client{Timeout: 5 * time.Second}

const ispCacheMax = 5000

// publicLookupIP validates that s is a literal, globally-routable IP and
// returns its canonical form (F-18). Rejects private, loopback, link-local,
// CGNAT (100.64/10), ULA, multicast, unspecified, and anything that isn't a
// bare IP literal — so user input can never be spliced into the lookup URL.
func publicLookupIP(s string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || !a.IsGlobalUnicast() {
		return "", false
	}
	if a.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return "", false
	}
	return a.String(), true
}

func lookupISP(rawIP string) map[string]string {
	result := map[string]string{"isp": "", "org": "", "country": "", "asn": ""}
	ip, ok := publicLookupIP(rawIP)
	if !ok {
		return result
	}
	ispCache.RLock()
	if v, ok := ispCache.data[ip]; ok {
		ispCache.RUnlock()
		return v
	}
	ispCache.RUnlock()

	// HTTPS provider (ip-api's free tier is plain HTTP only).
	resp, err := ispHTTPClient.Get("https://ipwho.is/" + ip + "?fields=success,country,connection")
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	var data struct {
		Success    bool   `json:"success"`
		Country    string `json:"country"`
		Connection struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&data); err != nil || !data.Success {
		return result
	}
	result["isp"] = data.Connection.ISP
	result["org"] = data.Connection.Org
	result["country"] = data.Country
	if data.Connection.ASN != 0 {
		result["asn"] = "AS" + strconv.Itoa(data.Connection.ASN)
	}

	ispCache.Lock()
	if len(ispCache.data) >= ispCacheMax {
		ispCache.data = make(map[string]map[string]string) // bounded: reset when full
	}
	ispCache.data[ip] = result
	ispCache.Unlock()
	return result
}

// handleISPLookup enriches a list of IPs with ISP/ASN data.
// ispLookupLimiter keeps one user from turning this endpoint into a relay that
// exhausts the third-party lookup service's quota for everyone.
var ispLookupLimiter = NewRateLimiter(1*time.Minute, 20)

func handleISPLookup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		if c := auth.GetClaims(r); c != nil && c.Username != "" {
			key = "u:" + c.Username
		}
		if !ispLookupLimiter.Allow(key) {
			writeJSON(w, 429, map[string]string{"error": "too many lookups, try again shortly"})
			return
		}
		var body struct {
			IPs []string `json:"ips"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		result := make(map[string]map[string]string)
		// Lookup up to 20 IPs, skip private
		var wg sync.WaitGroup
		var mu sync.Mutex
		count := 0
		for _, ip := range body.IPs {
			if _, ok := publicLookupIP(ip); !ok || count >= 20 {
				continue
			}
			count++
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				info := lookupISP(ip)
				mu.Lock()
				result[ip] = info
				mu.Unlock()
			}(ip)
		}
		wg.Wait()
		writeJSON(w, 200, map[string]interface{}{"enriched": result})
	}
}
