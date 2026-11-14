package api

// manual_ioc.go — analyst-supplied indicators (source "manual"). They live in
// the same table the feeds use, so the live engine, the DNS/IP/hash matching
// and the retro-hunt all treat them like any feed indicator. Feed syncs only
// replace their own source, so manual entries survive.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

const manualIOCSource = "manual"

var (
	manualHashRe   = regexp.MustCompile(`^[a-f0-9]+$`)
	manualDomainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// normalizeManualIOC validates and canonicalises one indicator.
func normalizeManualIOC(typ, val string) (string, string, error) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	val = strings.TrimSpace(val)
	switch typ {
	case "ip":
		ip := net.ParseIP(val)
		if ip == nil {
			return "", "", fmt.Errorf("not a valid IP address")
		}
		return typ, ip.String(), nil
	case "domain":
		d := strings.ToLower(strings.TrimSuffix(val, "."))
		if !manualDomainRe.MatchString(d) {
			return "", "", fmt.Errorf("not a valid domain name")
		}
		return typ, d, nil
	case "hash":
		h := strings.ToLower(val)
		if i := strings.Index(h, "="); i >= 0 { // sha256=... form
			h = h[i+1:]
		}
		if (len(h) != 32 && len(h) != 40 && len(h) != 64) || !manualHashRe.MatchString(h) {
			return "", "", fmt.Errorf("hash must be MD5, SHA-1 or SHA-256 in hex")
		}
		return typ, h, nil
	}
	return "", "", fmt.Errorf("type must be ip, domain or hash")
}

func manualIOCView(i store.IOCIndicator) map[string]interface{} {
	return map[string]interface{}{
		"id": i.ID, "type": i.IOCType, "value": i.Value, "label": i.Malware,
		"severity": i.Severity, "expires_at": i.ExpiresAt, "created_at": i.CreatedAt,
	}
}

func handleListManualIOCs(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.ListIOCsBySource(r.Context(), manualIOCSource, 1000)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not list indicators"})
			return
		}
		out := make([]map[string]interface{}, 0, len(rows))
		for _, i := range rows {
			out = append(out, manualIOCView(i))
		}
		writeJSON(w, 200, map[string]interface{}{"indicators": out})
	}
}

func handleAddManualIOC(db *store.DB, ti *ThreatIntelEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Type        string `json:"type"`
			Value       string `json:"value"`
			Label       string `json:"label"`
			Severity    int    `json:"severity"`
			ExpiresDays int    `json:"expires_days"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		typ, val, err := normalizeManualIOC(req.Type, req.Value)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		sev := req.Severity
		if sev < 1 || sev > 5 {
			sev = 4
		}
		label := strings.TrimSpace(req.Label)
		if len([]rune(label)) > 80 {
			label = string([]rune(label)[:80])
		}
		ioc := store.IOCIndicator{Source: manualIOCSource, IOCType: typ, Value: val, Malware: label,
			ThreatType: "manual", Confidence: 90, Severity: sev}
		if req.ExpiresDays > 0 && req.ExpiresDays <= 3650 {
			t := time.Now().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour)
			ioc.ExpiresAt = &t
		}
		if err := db.StoreIOC(r.Context(), ioc); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not save indicator"})
			return
		}
		invalidateIOCCache()
		if ti != nil { // hunt retained history for this indicator right away
			go ti.retroHunt(context.Background(), manualIOCSource, time.Now().Add(-time.Minute))
		}
		writeJSON(w, 201, map[string]interface{}{"ok": true, "type": typ, "value": val})
	}
}

func handleDeleteManualIOC(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		ok, err := db.DeleteIOCByID(r.Context(), id, manualIOCSource)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "delete failed"})
			return
		}
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "not found (only manual indicators can be deleted here)"})
			return
		}
		invalidateIOCCache()
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

// invalidateIOCCache makes the detection engine reload indicators on its next
// event instead of waiting for the cache TTL.
func invalidateIOCCache() {
	detectionIOCCache.mu.Lock()
	detectionIOCCache.at = time.Time{}
	detectionIOCCache.mu.Unlock()
}
