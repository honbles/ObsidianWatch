package api

// cloud_azure_assets.go — Azure Asset Inventory (CMDB)
//
// Uses Azure Resource Graph API to enumerate all resources across a subscription
// in a single efficient query. Far more efficient than per-type REST calls.
//
// Tracks change deltas and fires alerts on critical resource disappearance.
//
// Also upgrades the Activity Log API version from 2015-04-01 → 2022-06-01.
//
// Required permissions: Reader role on the subscription
// Required API: management.azure.com (already used for everything else)

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type AzureAsset struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"`          // e.g. microsoft.compute/virtualmachines
	ShortType     string            `json:"short_type"`    // e.g. Virtual Machines
	ResourceGroup string            `json:"resource_group"`
	Location      string            `json:"location"`
	Tags          map[string]string `json:"tags,omitempty"`
	State         string            `json:"state"`
	FirstSeen     time.Time         `json:"first_seen"`
	LastSeen      time.Time         `json:"last_seen"`
	HasFindings   bool              `json:"has_findings"`
	FindingCount  int               `json:"finding_count"`
}

type AzureAssetInventory struct {
	ConnectorID    int64             `json:"connector_id"`
	SubscriptionID string            `json:"subscription_id"`
	ScannedAt      time.Time         `json:"scanned_at"`
	Assets         []AzureAsset      `json:"assets"`
	TotalAssets    int               `json:"total_assets"`
	ByType         map[string]int    `json:"by_type"`
	NewAssets      []string          `json:"new_assets,omitempty"`
	DeletedAssets  []string          `json:"deleted_assets,omitempty"`
	Errors         []string          `json:"errors,omitempty"`
}

// ── Resource Graph API ────────────────────────────────────────────────────────

// RunAzureAssetInventory enumerates all resources in an Azure subscription
// using the Resource Graph API (single query, highly efficient).
//
// AZ-11: setting is the connector's subscription_id value (one ID, a list, or
// "*"); every resolved subscription is inventoried in the same Resource Graph
// query. fallbackSub is used when the setting cannot be resolved.
func RunAzureAssetInventory(ctx context.Context, tenantID, clientID, clientSecret, setting, fallbackSub string,
	connID int64, db *store.DB, logger *slog.Logger) (*AzureAssetInventory, error) {

	start := time.Now()
	inv := &AzureAssetInventory{
		ConnectorID: connID,
		ScannedAt:   start,
		ByType:      make(map[string]int),
	}

	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
	if err != nil {
		return nil, fmt.Errorf("asset inventory: auth failed: %w", err)
	}
	subs := azureInventorySubs(ctx, token.AccessToken, setting, fallbackSub, inv)
	if len(subs) == 0 {
		return nil, fmt.Errorf("asset inventory: no subscription to inventory")
	}
	subID := strings.Join(subs, ",")
	inv.SubscriptionID = subID

	var allAssets []AzureAsset
	skipToken := ""

	for {
		assets, next, err := queryResourceGraph(ctx, token.AccessToken, subs, skipToken)
		if err != nil {
			inv.Errors = append(inv.Errors, "resource graph: "+err.Error())
			break
		}
		allAssets = append(allAssets, assets...)
		if next == "" {
			break
		}
		skipToken = next
		// Rate limit protection
		select {
		case <-ctx.Done():
			return inv, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	now := time.Now()
	for i := range allAssets {
		allAssets[i].FirstSeen = now
		allAssets[i].LastSeen = now
		allAssets[i].ShortType = shortAzureType(allAssets[i].Type)
		inv.ByType[allAssets[i].ShortType]++
	}

	// Load previous inventory and compute deltas
	prev, _ := loadAzureAssetInventory(ctx, db, connID)
	if prev != nil {
		prevMap := make(map[string]AzureAsset, len(prev.Assets))
		for _, a := range prev.Assets {
			prevMap[a.ID] = a
		}

		var newIDs, deletedIDs []string
		currMap := make(map[string]struct{}, len(allAssets))
		for i, a := range allAssets {
			currMap[a.ID] = struct{}{}
			if old, exists := prevMap[a.ID]; exists {
				allAssets[i].FirstSeen = old.FirstSeen
			} else {
				newIDs = append(newIDs, a.ID)
			}
		}
		for _, a := range prev.Assets {
			if _, exists := currMap[a.ID]; !exists {
				deletedIDs = append(deletedIDs, a.ID)
			}
		}

		inv.NewAssets = newIDs
		inv.DeletedAssets = deletedIDs

		if len(deletedIDs) > 0 {
			fireAzureAssetDeletionAlerts(ctx, db, deletedIDs, subID, connID, logger)
		}
	}

	inv.Assets = allAssets
	inv.TotalAssets = len(allAssets)

	if err := saveAzureAssetInventory(ctx, db, inv); err != nil {
		logger.Warn("azure asset inventory: persist failed", "err", err)
	}

	return inv, nil
}

// queryResourceGraph calls the Azure Resource Graph API
func queryResourceGraph(ctx context.Context, token string, subs []string, skipToken string) ([]AzureAsset, string, error) {
	query := `Resources
| project id, name, type, resourceGroup, location, tags
| order by type asc, name asc`

	body := map[string]interface{}{
		"subscriptions": subs,
		"query":         query,
		"options": map[string]interface{}{
			"$top":  1000,
			"$skip": 0,
		},
	}
	if skipToken != "" {
		body["options"].(map[string]interface{})["$skipToken"] = skipToken
	}

	bodyJSON, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01",
		strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 403 {
		return nil, "", fmt.Errorf("permission denied — Reader role required on subscription")
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("resource graph API %d: %s", resp.StatusCode,
			string(respBody)[:minInt(200, len(respBody))])
	}

	var result struct {
		Data struct {
			Rows    [][]interface{} `json:"rows"`
			Columns []struct {
				Name string `json:"name"`
			} `json:"columns"`
		} `json:"data"`
		SkipToken string `json:"$skipToken"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, "", err
	}

	// Build column index
	colIdx := map[string]int{}
	for i, col := range result.Data.Columns {
		colIdx[col.Name] = i
	}

	assets := make([]AzureAsset, 0, len(result.Data.Rows))
	for _, row := range result.Data.Rows {
		a := AzureAsset{State: "active"}
		if i, ok := colIdx["id"]; ok && i < len(row) {
			a.ID = fmt.Sprintf("%v", row[i])
		}
		if i, ok := colIdx["name"]; ok && i < len(row) {
			a.Name = fmt.Sprintf("%v", row[i])
		}
		if i, ok := colIdx["type"]; ok && i < len(row) {
			a.Type = strings.ToLower(fmt.Sprintf("%v", row[i]))
		}
		if i, ok := colIdx["resourceGroup"]; ok && i < len(row) {
			a.ResourceGroup = fmt.Sprintf("%v", row[i])
		}
		if i, ok := colIdx["location"]; ok && i < len(row) {
			a.Location = fmt.Sprintf("%v", row[i])
		}
		if i, ok := colIdx["tags"]; ok && i < len(row) && row[i] != nil {
			if tagMap, ok := row[i].(map[string]interface{}); ok {
				a.Tags = make(map[string]string)
				for k, v := range tagMap {
					a.Tags[k] = fmt.Sprintf("%v", v)
				}
			}
		}
		if a.ID != "" && a.Name != "" {
			assets = append(assets, a)
		}
	}

	return assets, result.SkipToken, nil
}

// ── Persistence ───────────────────────────────────────────────────────────────

func saveAzureAssetInventory(ctx context.Context, db *store.DB, inv *AzureAssetInventory) error {
	data, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return db.SetSetting(ctx, fmt.Sprintf("assets:azure:%d", inv.ConnectorID), string(data))
}

func loadAzureAssetInventory(ctx context.Context, db *store.DB, connID int64) (*AzureAssetInventory, error) {
	val, err := db.GetSetting(ctx, fmt.Sprintf("assets:azure:%d", connID))
	if err != nil || val == "" {
		return nil, nil
	}
	var inv AzureAssetInventory
	if err := json.Unmarshal([]byte(val), &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

// ── Delta alerts ──────────────────────────────────────────────────────────────

func fireAzureAssetDeletionAlerts(ctx context.Context, db *store.DB, deleted []string,
	subID string, connID int64, logger *slog.Logger) {

	criticalTypes := []string{
		"microsoft.sql/servers", "microsoft.keyvault/vaults",
		"microsoft.containerservice/managedclusters",
		"microsoft.storage/storageaccounts",
		"microsoft.recoveryservices/vaults",
		"microsoft.network/azurefirewalls",
		"microsoft.compute/disks",
		"microsoft.documentdb/databaseaccounts",
	}

	for _, id := range deleted {
		lower := strings.ToLower(id)
		for _, t := range criticalTypes {
			if strings.Contains(lower, strings.ReplaceAll(t, "/", "/")) {
				day := time.Now().UTC().Format("20060102")
				shortName := id
				if parts := strings.Split(id, "/"); len(parts) > 0 {
					shortName = parts[len(parts)-1]
				}
				dedupKey := fmt.Sprintf("asset:az:deleted:%s:d:%s", sanitiseKey(shortName), day)
				alert := store.Alert{
					Title: "[T1485] Azure Critical Resource Disappeared from Inventory",
					Description: fmt.Sprintf("Resource '%s' was present in the previous inventory scan but is no longer detected. This may indicate deletion, resource move, or infrastructure tampering.\n\nSubscription: %s\nResource: %s",
						shortName, subID, id),
					Severity:  4,
					Host:      subID,
					EventType: "cloud.azure_assets",
					EventID:   dedupKey,
					AgentID:   fmt.Sprintf("azure-assets-%d", connID),
				}
				if _, inserted, err := db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
					logger.Info("azure asset deletion alert", "resource", shortName)
				}
				break
			}
		}
	}
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

func handleGetAzureAssets(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscan(idStr, &id)
		inv, err := loadAzureAssetInventory(r.Context(), db, id)
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

func handleRunAzureAssets(db *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscan(idStr, &id)

		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil {
			http.Error(w, "connector not found", 404)
			return
		}
		if conn.Provider != "azure" {
			http.Error(w, "asset inventory only supported for Azure", 400)
			return
		}

		tenantID     := conn.Credentials["tenant_id"]
		clientID     := conn.Credentials["client_id"]
		clientSecret := conn.Credentials["client_secret"]
		subSetting   := conn.Credentials["subscription_id"]
		subFallback  := conn.AccountID

		go func() {
			scanCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			if _, err := RunAzureAssetInventory(scanCtx, tenantID, clientID, clientSecret, subSetting, subFallback, id, db, logger); err != nil {
				logger.Warn("azure asset inventory failed", "id", id, "err", err)
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "scanning"})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

var azureTypeLabels = map[string]string{
	"microsoft.compute/virtualmachines":            "Virtual Machines",
	"microsoft.compute/disks":                      "Managed Disks",
	"microsoft.network/networksecuritygroups":       "NSGs",
	"microsoft.network/virtualnetworks":             "Virtual Networks",
	"microsoft.network/publicipaddresses":           "Public IPs",
	"microsoft.network/applicationgateways":        "App Gateways",
	"microsoft.network/azurefirewalls":              "Azure Firewalls",
	"microsoft.storage/storageaccounts":            "Storage Accounts",
	"microsoft.sql/servers":                        "SQL Servers",
	"microsoft.documentdb/databaseaccounts":        "Cosmos DB",
	"microsoft.keyvault/vaults":                    "Key Vaults",
	"microsoft.containerservice/managedclusters":   "AKS Clusters",
	"microsoft.web/sites":                          "App Services",
	"microsoft.logic/workflows":                    "Logic Apps",
	"microsoft.automation/automationaccounts":      "Automation Accounts",
	"microsoft.recoveryservices/vaults":            "Recovery Vaults",
	"microsoft.insights/components":                "App Insights",
	"microsoft.operationalinsights/workspaces":     "Log Analytics",
	"microsoft.containerregistry/registries":       "Container Registries",
}

func shortAzureType(t string) string {
	if label, ok := azureTypeLabels[t]; ok {
		return label
	}
	// Fallback: take last segment after /
	parts := strings.Split(t, "/")
	if len(parts) >= 2 {
		p := parts[len(parts)-1]
	if len(p) > 0 { return strings.ToUpper(p[:1]) + p[1:] }
	return p
	}
	return t
}

// ── Unified routing handlers (GCP + Azure) ────────────────────────────────────

func handleCloudAssets(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscan(idStr, &id)
		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil {
			http.Error(w, "connector not found", 404)
			return
		}
		if conn.Provider == "azure" {
			handleGetAzureAssets(db)(w, r)
		} else if conn.Provider == "aws" {
			handleGetAWSAssets(db)(w, r)
		} else {
			handleGetGCPAssets(db)(w, r)
		}
	}
}

func handleRunCloudAssets(db *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscan(idStr, &id)
		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil {
			http.Error(w, "connector not found", 404)
			return
		}
		if conn.Provider == "azure" {
			handleRunAzureAssets(db, logger)(w, r)
		} else if conn.Provider == "aws" {
			handleRunAWSAssets(db, logger)(w, r)
		} else {
			handleRunGCPAssets(db, logger)(w, r)
		}
	}
}

const azureInventoryMaxSubs = 100

// azureInventorySubs resolves the subscriptions to inventory, recording any
// resolution problem on inv and falling back to fallbackSub.
func azureInventorySubs(ctx context.Context, token, setting, fallbackSub string, inv *AzureAssetInventory) []string {
	var subs []string
	if strings.TrimSpace(setting) != "" {
		var err error
		subs, err = resolveAzureSubscriptions(ctx, token, setting)
		if err != nil {
			inv.Errors = append(inv.Errors, "subscriptions: "+err.Error())
			subs = nil
		}
	}
	if len(subs) == 0 && fallbackSub != "" {
		subs = []string{fallbackSub}
	}
	if len(subs) > azureInventoryMaxSubs {
		inv.Errors = append(inv.Errors, fmt.Sprintf("%d subscription(s) not inventoried (limit %d)", len(subs)-azureInventoryMaxSubs, azureInventoryMaxSubs))
		subs = subs[:azureInventoryMaxSubs]
	}
	return subs
}
