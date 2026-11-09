package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"obsidianwatch/management/internal/store"
)

// G-40: alert when a scan finds a critical misconfiguration that was not
// present in the previous scan. Findings are matched on (title, resource)
// rather than ID because GCP finding IDs are positional.

func cspmFindingKey(f CSPMFinding) string {
	return strings.ToLower(f.Title) + "\x00" + strings.ToLower(f.Resource)
}

// alertNewCriticalFindings compares prevJSON (the previously persisted scan
// result for this connector, "" if none) with the new findings. No alerts on
// the very first scan (everything would be "new").
func alertNewCriticalFindings(ctx context.Context, db *store.DB, provider string, connID int64, scope, prevJSON string, findings []CSPMFinding, logger *slog.Logger) {
	if prevJSON == "" {
		return
	}
	var prev struct {
		Findings []CSPMFinding `json:"findings"`
	}
	if json.Unmarshal([]byte(prevJSON), &prev) != nil {
		return
	}
	known := make(map[string]bool, len(prev.Findings))
	for _, f := range prev.Findings {
		known[cspmFindingKey(f)] = true
	}
	fired := 0
	for _, f := range findings {
		if strings.ToLower(f.Severity) != "critical" || f.Status == "suppressed" {
			continue
		}
		k := cspmFindingKey(f)
		if known[k] {
			continue
		}
		sum := sha256.Sum256([]byte(provider + "|" + scope + "|" + k))
		alert := store.Alert{
			Title: fmt.Sprintf("[CSPM] New critical misconfiguration: %s", f.Title),
			Description: fmt.Sprintf("A critical posture finding appeared since the previous scan.\n\nProvider: %s\nScope: %s\nResource: %s\n\n%s\n\nRemediation: %s",
				strings.ToUpper(provider), scope, f.Resource, f.Description, f.Remediation),
			Severity:  5,
			Host:      scope,
			EventType: "cloud.cspm",
			EventID:   "cspm:new:" + hex.EncodeToString(sum[:8]),
			AgentID:   fmt.Sprintf("%s-cspm-%d", provider, connID),
		}
		if _, inserted, err := db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
			fired++
		}
	}
	if fired > 0 {
		logger.Info("cspm: new critical findings alerted", "provider", provider, "connector", connID, "count", fired)
	}
}
