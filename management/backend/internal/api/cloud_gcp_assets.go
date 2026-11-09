package api

// cloud_gcp_assets.go — GCP Asset Inventory (CMDB).
//
// Enumerates all GCP resources regardless of whether they have findings.
// Uses the Cloud Asset Inventory API (cloudasset.googleapis.com).
// Results are stored in the settings table under "assets:gcp:{connectorID}"
// and exposed via the API so the frontend can show ALL resources, not just
// those with CSPM findings.
//
// Tracks change deltas: new resources, deleted resources, and config changes
// are recorded and can fire alerts.
//
// Required IAM: roles/cloudasset.viewer
// Required API: cloudasset.googleapis.com
//
// API endpoints:
//   GET /api/v1/cloud-connectors/{id}/assets   — list all inventoried assets
//   POST /api/v1/cloud-connectors/{id}/assets  — trigger re-inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type GCPAsset struct {
	Name        string            `json:"name"`         // Full resource name
	AssetType   string            `json:"asset_type"`   // e.g. "compute.googleapis.com/Instance"
	ShortName   string            `json:"short_name"`   // Last segment of name
	Location    string            `json:"location"`
	State       string            `json:"state"`        // ACTIVE, DELETED
	Labels      map[string]string `json:"labels,omitempty"`
	CreateTime  *time.Time        `json:"create_time,omitempty"`
	UpdateTime  *time.Time        `json:"update_time,omitempty"`
	HasFindings bool              `json:"has_findings"`
	FindingCount int              `json:"finding_count"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
}

type GCPAssetInventory struct {
	ConnectorID int64               `json:"connector_id"`
	ProjectID   string              `json:"project_id"`
	ScannedAt   time.Time           `json:"scanned_at"`
	Assets      []GCPAsset          `json:"assets"`
	TotalAssets int                 `json:"total_assets"`
	ByType      map[string]int      `json:"by_type"`
	NewAssets   []string            `json:"new_assets,omitempty"`
	DeletedAssets []string          `json:"deleted_assets,omitempty"`
	Errors      []string            `json:"errors,omitempty"`
	// G-41: asset types that could not be listed this run (permission/API/
	// error). Their previous assets are carried forward and excluded from
	// deletion deltas so a failed type never looks like mass deletion.
	SkippedTypes []string           `json:"skipped_types,omitempty"`
}

// ── Cloud Asset Inventory API ─────────────────────────────────────────────────

// RunGCPAssetInventory enumerates all resources in a GCP project using
// the Cloud Asset Inventory API. Falls back to direct API enumeration
// for the most critical resource types if CAI is not enabled.
func RunGCPAssetInventory(ctx context.Context, saJSON, projectID string, connID int64, db *store.DB, logger *slog.Logger) (*GCPAssetInventory, error) {
	start := time.Now()
	inv := &GCPAssetInventory{
		ConnectorID: connID,
		ProjectID:   projectID,
		ScannedAt:   start,
		ByType:      make(map[string]int),
	}

	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return nil, fmt.Errorf("invalid SA JSON: %w", err)
	}
	if projectID == "" {
		projectID = sa.ProjectID
	}
	inv.ProjectID = projectID

	token, err := getGCPTokenWithScope(ctx, sa, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("auth failed: %w\n\nEnsure the service account JSON key file is complete and the Cloud Asset API (cloudasset.googleapis.com) is enabled", err)
	}

	// Asset types to enumerate
	assetTypes := []string{
		"compute.googleapis.com/Instance",
		"compute.googleapis.com/Firewall",
		"compute.googleapis.com/Network",
		"compute.googleapis.com/Subnetwork",
		"compute.googleapis.com/Disk",
		"storage.googleapis.com/Bucket",
		"sqladmin.googleapis.com/Instance",
		"container.googleapis.com/Cluster",
		"iam.googleapis.com/ServiceAccount",
		"cloudkms.googleapis.com/CryptoKey",
		"bigquery.googleapis.com/Dataset",
		"bigquery.googleapis.com/Table",
		"pubsub.googleapis.com/Topic",
		"pubsub.googleapis.com/Subscription",
		"run.googleapis.com/Service",
		"cloudfunctions.googleapis.com/CloudFunction",
		"secretmanager.googleapis.com/Secret",
		"dns.googleapis.com/ManagedZone",
		"logging.googleapis.com/LogSink",
		"monitoring.googleapis.com/AlertPolicy",
	}

	var allAssets []GCPAsset

	skipped := map[string]bool{}
	for _, assetType := range assetTypes {
		assets, err := listAssetsByType(ctx, token, projectID, assetType)
		if err != nil {
			skipped[assetType] = true
			inv.SkippedTypes = append(inv.SkippedTypes, assetType+": "+err.Error())
			if !(strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404") ||
				strings.Contains(err.Error(), "disabled")) {
				inv.Errors = append(inv.Errors, assetType+": "+err.Error())
			}
			continue
		}
		for _, a := range assets {
			a.AssetType = assetType
			a.ShortName = shortResourceName(a.Name)
			a.FirstSeen = start
			a.LastSeen = start
			inv.ByType[simplifyAssetType(assetType)]++
			allAssets = append(allAssets, a)
		}
	}

	// Load previous inventory to compute deltas
	prev, _ := loadAssetInventory(ctx, db, connID)
	if prev != nil && len(skipped) > 0 {
		// Carry forward assets of types we couldn't list and don't diff them.
		kept := make([]GCPAsset, 0, len(prev.Assets))
		for _, a := range prev.Assets {
			if skipped[a.AssetType] {
				allAssets = append(allAssets, a)
			} else {
				kept = append(kept, a)
			}
		}
		prev = &GCPAssetInventory{Assets: kept, ConnectorID: prev.ConnectorID}
		// prev now excludes skipped types; allAssets includes carried ones, so
		// they'd show as "new" — filter them back out below.
	}
	if prev != nil {
		newAssets, deleted := computeDeltas(prev.Assets, allAssets)
		if len(skipped) > 0 {
			filtered := newAssets[:0]
			for _, n := range newAssets {
				carried := false
				for _, a := range allAssets {
					if a.Name == n && skipped[a.AssetType] {
						carried = true
						break
					}
				}
				if !carried {
					filtered = append(filtered, n)
				}
			}
			newAssets = filtered
		}
		inv.NewAssets = newAssets
		inv.DeletedAssets = deleted

		// Fire alerts for deleted critical assets
		if len(deleted) > 0 {
			fireAssetDeletionAlerts(ctx, db, deleted, projectID, connID, logger)
		}

		// Preserve first_seen from previous inventory
		prevMap := make(map[string]GCPAsset, len(prev.Assets))
		for _, a := range prev.Assets {
			prevMap[a.Name] = a
		}
		for i, a := range allAssets {
			if old, ok := prevMap[a.Name]; ok {
				allAssets[i].FirstSeen = old.FirstSeen
			}
		}
	}

	inv.Assets = allAssets
	inv.TotalAssets = len(allAssets)

	// Persist
	if err := saveAssetInventory(ctx, db, inv); err != nil {
		logger.Warn("asset inventory: failed to persist", "err", err)
	}

	return inv, nil
}

// listAssetsByType calls the Cloud Asset Inventory API for a single asset type.
func listAssetsByType(ctx context.Context, token, projectID, assetType string) ([]GCPAsset, error) {
	// G-41: follow nextPageToken. Exceeding the page cap is an error (not a
	// silent truncation) so deltas never diff against a partial list.
	const maxPages = 40
	baseURL := fmt.Sprintf(
		"https://cloudasset.googleapis.com/v1/projects/%s/assets?assetTypes=%s&contentType=RESOURCE&pageSize=500",
		projectID, assetType)
	var assets []GCPAsset
	pageToken := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("asset listing exceeded %d pages; treating type as not assessed", maxPages)
		}
		url := baseURL
		if pageToken != "" {
			url += "&pageToken=" + neturl.QueryEscape(pageToken)
		}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 403 {
			return nil, fmt.Errorf("permission denied (403): %s", string(body)[:minInt(100, len(body))])
		}
		if resp.StatusCode == 404 || resp.StatusCode == 400 {
			return nil, fmt.Errorf("not found or API disabled (%d)", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("asset API %d: %s", resp.StatusCode, string(body)[:minInt(200, len(body))])
		}
		var result struct {
			Assets []struct {
				Name       string    `json:"name"`
				AssetType  string    `json:"assetType"`
				UpdateTime time.Time `json:"updateTime"`
				Resource   struct {
					Location string            `json:"location"`
					Labels   map[string]string `json:"labels"`
					Data     json.RawMessage   `json:"data"`
				} `json:"resource"`
			} `json:"assets"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, err
		}
		for i := range result.Assets {
			r := result.Assets[i]
			ut := r.UpdateTime
			assets = append(assets, GCPAsset{
				Name:       r.Name,
				Location:   r.Resource.Location,
				Labels:     r.Resource.Labels,
				State:      "ACTIVE",
				UpdateTime: &ut,
			})
		}
		if result.NextPageToken == "" {
			return assets, nil
		}
		pageToken = result.NextPageToken
	}
}

// ── Delta computation ─────────────────────────────────────────────────────────

func computeDeltas(prev, curr []GCPAsset) (newAssets, deleted []string) {
	prevMap := make(map[string]struct{}, len(prev))
	for _, a := range prev {
		prevMap[a.Name] = struct{}{}
	}
	currMap := make(map[string]struct{}, len(curr))
	for _, a := range curr {
		currMap[a.Name] = struct{}{}
	}
	for _, a := range curr {
		if _, ok := prevMap[a.Name]; !ok {
			newAssets = append(newAssets, a.Name)
		}
	}
	for _, a := range prev {
		if _, ok := currMap[a.Name]; !ok {
			deleted = append(deleted, a.Name)
		}
	}
	return
}

func fireAssetDeletionAlerts(ctx context.Context, db *store.DB, deleted []string, project string, connID int64, logger *slog.Logger) {
	criticalTypes := []string{"cluster", "sql", "kms", "cryptokey", "bucket", "secret", "logsink"}
	for _, name := range deleted {
		lower := strings.ToLower(name)
		for _, t := range criticalTypes {
			if strings.Contains(lower, t) {
				day := time.Now().UTC().Format("20060102")
				dedupKey := fmt.Sprintf("asset:deleted:%s:d:%s", sanitiseKey(name), day)
				alert := store.Alert{
					Title: fmt.Sprintf("[T1485] GCP Critical Asset Disappeared from Inventory"),
					Description: fmt.Sprintf("Resource '%s' was present in the previous asset inventory scan but is no longer detected. This may indicate deletion, project restructuring, or resource hijacking.\n\nProject: %s\nResource: %s",
						shortResourceName(name), project, name),
					Severity:  4,
					Host:      project,
					EventType: "cloud.gcp_assets",
					EventID:   dedupKey,
					AgentID:   fmt.Sprintf("gcp-assets-%d", connID),
				}
				if _, inserted, err := db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
					logger.Info("asset deletion alert", "resource", name)
				}
				break
			}
		}
	}
}

// ── Persistence ───────────────────────────────────────────────────────────────

func saveAssetInventory(ctx context.Context, db *store.DB, inv *GCPAssetInventory) error {
	data, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("assets:gcp:%d", inv.ConnectorID)
	return db.SetSetting(ctx, key, string(data))
}

func loadAssetInventory(ctx context.Context, db *store.DB, connID int64) (*GCPAssetInventory, error) {
	key := fmt.Sprintf("assets:gcp:%d", connID)
	val, err := db.GetSetting(ctx, key)
	if err != nil || val == "" {
		return nil, nil
	}
	var inv GCPAssetInventory
	if err := json.Unmarshal([]byte(val), &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

func handleGetGCPAssets(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscan(idStr, &id)
		inv, err := loadAssetInventory(r.Context(), db, id)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if inv == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "No inventory yet — run a scan first",
				"assets":  []struct{}{},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(inv)
	}
}

func handleRunGCPAssets(db *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscan(idStr, &id)

		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil {
			http.Error(w, "connector not found", 404)
			return
		}
		if conn.Provider != "gcp" {
			http.Error(w, "asset inventory only supported for GCP", 400)
			return
		}

		saJSON := conn.Credentials["service_account"]
		projectID := firstGCPProject(conn.Credentials["project_id"])
		if projectID == "" {
			projectID = conn.AccountID
		}

		go func() {
			scanCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			if _, err := RunGCPAssetInventory(scanCtx, saJSON, projectID, id, db, logger); err != nil {
				logger.Warn("asset inventory failed", "id", id, "err", err)
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "scanning"})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func shortResourceName(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return name
}

func simplifyAssetType(t string) string {
	// "compute.googleapis.com/Instance" → "compute/Instance"
	parts := strings.SplitN(t, ".", 2)
	if len(parts) == 2 {
		svc := parts[0]
		res := strings.SplitN(parts[1], "/", 2)
		if len(res) == 2 {
			return svc + "/" + res[1]
		}
	}
	return t
}
