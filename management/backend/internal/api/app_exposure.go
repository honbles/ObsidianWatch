package api

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/lib/pq"

	"obsidianwatch/management/internal/store"
)

// Exposure inference. The analyst's setting always wins; when it is "unknown" the exposure is inferred
// from the client addresses the service has been seen answering (7 days of per-minute failure counters).
// A public client address means internet-facing; only private ones mean internal; nothing means unknown.
// The reason is shown next to the value so an analyst can confirm or override it.

type appExposureInference struct {
	Exposure string
	Reason   string
}

func appExposureIsPublic(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() &&
		!ip.IsMulticast() && !ip.IsLinkLocalMulticast()
}

// appInferExposureFromIPs classifies client/peer addresses; unparseable entries (masked or empty) are skipped.
func appInferExposureFromIPs(ips []string) appExposureInference {
	var private int
	for _, raw := range ips {
		s := strings.TrimSpace(raw)
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if appExposureIsPublic(ip) {
			return appExposureInference{"internet", fmt.Sprintf("a public client address (%s) was seen in the last 7 days", s)}
		}
		if ip.IsPrivate() {
			private++
		}
	}
	if private > 0 {
		return appExposureInference{"internal", "only private client addresses were seen in the last 7 days"}
	}
	return appExposureInference{"unknown", "no client addresses observed yet"}
}

// EffectiveExposure is the analyst's setting, or the inferred value when the setting is "unknown".
func (s appServiceSettings) EffectiveExposure() string {
	if s.Exposure != "unknown" && s.Exposure != "" {
		return s.Exposure
	}
	if s.ExposureInferred != "" {
		return s.ExposureInferred
	}
	return "unknown"
}

// appApplyExposure fills the inferred fields of every setting whose exposure is still "unknown".
func appApplyExposure(ctx context.Context, idb *store.DB, ids []int64, settings map[int64]appServiceSettings) {
	if idb == nil || len(ids) == 0 {
		return
	}
	need := make([]int64, 0, len(ids))
	for _, id := range ids {
		st, ok := settings[id]
		if !ok || st.Exposure == "unknown" || st.Exposure == "" {
			need = append(need, id)
		}
	}
	if len(need) == 0 {
		return
	}
	rows, err := idb.QueryContext(ctx, `
		SELECT service_id, client_ip, peer_ip FROM (
		  SELECT DISTINCT ON (service_id, client_ip, peer_ip) service_id, client_ip, peer_ip
		  FROM app_client_stats WHERE service_id = ANY($1) AND minute > $2
		) d LIMIT 5000`, pq.Array(need), time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil {
		return
	}
	defer rows.Close()
	seen := map[int64][]string{}
	for rows.Next() {
		var id int64
		var c, p string
		if rows.Scan(&id, &c, &p) == nil {
			seen[id] = append(seen[id], c, p)
		}
	}
	for _, id := range need {
		st, ok := settings[id]
		if !ok {
			st = appDefaultSettings()
		}
		inf := appInferExposureFromIPs(seen[id])
		st.ExposureInferred, st.ExposureReason = inf.Exposure, inf.Reason
		settings[id] = st
	}
}
