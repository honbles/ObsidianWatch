package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// CloudConnectorEngine polls cloud providers every 5 minutes.
type CloudConnectorEngine struct {
	db               *store.DB
	eventDB          *store.DB
	logger           *slog.Logger
	correlation      *GCPCorrelationEngine
	baseline         *GCPBaselineEngine
	suppressor       *GCPSuppressor
	azureSuppressor  *AzureSuppressor
	azureCorrelation *AzureCorrelationEngine
	azureBaseline    *AzureBaselineEngine
	awsBaseline      *AWSBaselineEngine
}

func NewCloudConnectorEngine(db *store.DB, eventDB *store.DB, logger *slog.Logger) *CloudConnectorEngine {
	activeAzureSuppressor = NewAzureSuppressor(db)
	activeAWSSuppressor = NewAWSSuppressor(db)
	return &CloudConnectorEngine{
		db:               db,
		eventDB:          eventDB,
		logger:           logger,
		correlation:      NewGCPCorrelationEngine(db, logger),
		baseline:         NewGCPBaselineEngine(db, logger),
		suppressor:       NewGCPSuppressor(db),
		azureSuppressor:  activeAzureSuppressor,
		azureCorrelation: NewAzureCorrelationEngine(db, logger),
		azureBaseline:    NewAzureBaselineEngine(db, logger),
		awsBaseline:      NewAWSBaselineEngine(db, logger),
	}
}

// Suppressor returns the GCP suppressor for use in HTTP handlers.
func (e *CloudConnectorEngine) Suppressor() *GCPSuppressor { return e.suppressor }

// AzureSuppressor returns the Azure suppressor for use in HTTP handlers.
func (e *CloudConnectorEngine) AzureSuppressor() *AzureSuppressor { return e.azureSuppressor }

func (e *CloudConnectorEngine) Run(ctx context.Context) {
	e.logger.Info("cloud connector engine started")
	e.syncAll(ctx)
	// Run CSPM on startup for all GCP connectors
	go e.runCSPMAll(ctx)
	// Start GCP intelligence engines
	go e.correlation.Run(ctx)
	go e.baseline.Run(ctx)
	// Start Azure intelligence engines
	go e.azureCorrelation.Run(ctx)
	go e.azureBaseline.Run(ctx)
	go e.awsBaseline.Run(ctx)

	ticker := time.NewTicker(5 * time.Minute)
	cspmTicker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	defer cspmTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.syncAll(ctx)
			// Refresh suppression rules each cycle
			e.suppressor.Refresh(ctx)
		case <-cspmTicker.C:
			go e.runCSPMAll(ctx)
		}
	}
}

// runCSPMAll scans all GCP connectors with CSPM and persists results.
func (e *CloudConnectorEngine) runCSPMAll(ctx context.Context) {
	connectors, err := e.db.ListCloudConnectors(ctx)
	if err != nil {
		e.logger.Error("cspm: failed to list connectors", "err", err)
		return
	}
	for _, c := range connectors {
		if c.Provider == "aws" {
			e.scanAWSCSPM(ctx, c.ID)
			continue
		}
		if c.Provider == "azure" {
			conn, err := e.db.GetCloudConnectorRaw(ctx, c.ID)
			if err != nil {
				continue
			}
			tenantID := conn.Credentials["tenant_id"]
			clientID := conn.Credentials["client_id"]
			clientSecret := conn.Credentials["client_secret"]
			subID := conn.Credentials["subscription_id"]
			if subID == "" {
				subID = conn.AccountID
			}
			if tenantID == "" || clientID == "" || clientSecret == "" {
				continue
			}
			e.logger.Info("cspm: scanning Azure connector", "id", c.ID, "sub", subID)
			scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			azResult, azErr := RunAzureCSPMForConnector(scanCtx, tenantID, clientID, clientSecret, conn.Credentials["subscription_id"], conn.AccountID)
			cancel()
			if azErr != nil {
				e.logger.Error("cspm: azure scan failed", "id", c.ID, "err", azErr)
			} else {
				azResult.ConnectorID = c.ID
				applyAzureSuppression(azResult)
				resultJSON, _ := json.Marshal(azResult)
				key := fmt.Sprintf("cspm:azure:%d", c.ID)
				prevAz, _ := e.db.GetSetting(ctx, key)
				e.db.SetSetting(ctx, key, string(resultJSON))
				alertNewCriticalFindings(ctx, e.db, "azure", c.ID, subID, prevAz, azResult.Findings, e.logger)
				e.logger.Info("cspm: azure scan complete", "id", c.ID, "findings", azResult.TotalFindings)

				// Auto-generate compliance report from Azure findings
				azCSPMBridge := &CSPMResult{
					ConnectorID:   c.ID,
					ProjectID:     subID,
					ScannedAt:     azResult.ScannedAt,
					Findings:      azResult.Findings,
					TotalFindings: azResult.TotalFindings,
					Critical:      azResult.Critical,
					High:          azResult.High,
					Medium:        azResult.Medium,
					Low:           azResult.Low,
					Passed:        azResult.Passed,
					NotAssessed:   azResult.NotAssessed,
				}
				azCompReport := MapToCompliance(azCSPMBridge)
				azCompReport.ConnectorID = c.ID
				if azCompJSON, azCompErr := json.Marshal(azCompReport); azCompErr == nil {
					e.db.SetSetting(ctx, fmt.Sprintf("compliance:azure:%d", c.ID), string(azCompJSON))
					e.logger.Info("compliance: azure mapped", "id", c.ID, "summary", ComplianceSummary(azCompReport))
				}
			}
			continue
		}
		if c.Provider != "gcp" {
			continue
		}
		conn, err := e.db.GetCloudConnectorRaw(ctx, c.ID)
		if err != nil {
			continue
		}
		saJSON := conn.Credentials["service_account"]
		if saJSON == "" {
			continue
		}
		// Asset inventory and alert labelling stay on the first project.
		projectID := firstGCPProject(conn.Credentials["project_id"])
		if projectID == "" {
			projectID = conn.AccountID
		}
		e.logger.Info("cspm: scanning GCP connector", "id", c.ID)
		scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		result, err := RunGCPCSPMForConnector(scanCtx, conn.Credentials, conn.AccountID)
		cancel()
		if err != nil {
			e.logger.Error("cspm: scan failed", "id", c.ID, "err", err)
			continue
		}
		result.ConnectorID = c.ID
		resultJSON, err := json.Marshal(result)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("cspm:gcp:%d", c.ID)
		prevGCP, _ := e.db.GetSetting(ctx, key)
		if setErr := e.db.SetSetting(ctx, key, string(resultJSON)); setErr != nil {
			e.logger.Error("cspm: failed to persist result", "id", c.ID, "err", setErr)
		} else {
			e.logger.Info("cspm: scan complete", "id", c.ID, "findings", result.TotalFindings,
				"critical", result.Critical, "high", result.High)
		}
		alertNewCriticalFindings(ctx, e.db, "gcp", c.ID, projectID, prevGCP, result.Findings, e.logger)
		// G-40: scheduled asset inventory (drives asset-deletion alerts) —
		// previously only ran when someone clicked the button.
		invCtx, invCancel := context.WithTimeout(ctx, 5*time.Minute)
		if _, invErr := RunGCPAssetInventory(invCtx, saJSON, projectID, c.ID, e.db, e.logger); invErr != nil {
			e.logger.Warn("asset inventory: scheduled run failed", "id", c.ID, "err", invErr)
		}
		invCancel()
		// Also compute and persist compliance report
		compReport := MapToCompliance(result)
		compReport.ConnectorID = c.ID
		if compJSON, compErr := json.Marshal(compReport); compErr == nil {
			compKey := fmt.Sprintf("compliance:gcp:%d", c.ID)
			e.db.SetSetting(ctx, compKey, string(compJSON))
			e.logger.Info("compliance: mapped", "id", c.ID, "summary", ComplianceSummary(compReport))
		}
	}
}

func (e *CloudConnectorEngine) SyncOne(ctx context.Context, id int64) error {
	conn, err := e.db.GetCloudConnectorRaw(ctx, id)
	if err != nil {
		return err
	}
	return e.syncConnector(ctx, conn)
}

func (e *CloudConnectorEngine) syncAll(ctx context.Context) {
	connectors, err := e.db.ListCloudConnectors(ctx)
	if err != nil {
		return
	}
	for _, c := range connectors {
		// Retry errored connectors after 30 min cooldown
		if c.Status == "error" && c.LastSync != nil {
			if time.Since(*c.LastSync) < 30*time.Minute {
				continue
			}
		}
		conn, err := e.db.GetCloudConnectorRaw(ctx, c.ID)
		if err != nil {
			continue
		}
		go e.syncConnector(ctx, conn)
	}
}

func (e *CloudConnectorEngine) syncConnector(ctx context.Context, conn *store.CloudConnector) error {
	// G-05: skip if a sync for this connector is already running.
	guardKey := fmt.Sprintf("cloud:%d", conn.ID)
	if !tryAcquireSync(guardKey) {
		e.logger.Info("cloud sync skipped: previous sync still running", "provider", conn.Provider, "id", conn.ID)
		return nil
	}
	defer releaseSync(guardKey)
	// Retry up to 3 times with exponential backoff
	var ingested int
	var cursor string
	var syncErr error
	backoff := 5 * time.Second

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		syncCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		ingested, cursor, syncErr = e.doSync(syncCtx, conn)
		cancel()

		if syncErr == nil {
			break
		}
		// Don't retry auth errors — they won't fix themselves
		if isAuthError(syncErr) {
			break
		}
		e.logger.Warn("cloud sync attempt failed, retrying",
			"provider", conn.Provider, "attempt", attempt+1, "err", syncErr)
	}

	status := "connected"
	errMsg := ""
	if syncErr != nil {
		status = "error"
		errMsg = syncErr.Error()
		e.logger.Warn("cloud sync failed", "provider", conn.Provider, "id", conn.ID, "err", syncErr)
	} else if ingested > 0 {
		e.logger.Info("cloud sync complete", "provider", conn.Provider, "id", conn.ID, "ingested", ingested)
	}

	e.db.UpdateCloudConnectorStatus(ctx, conn.ID, status, errMsg, int64(ingested), cursor)
	return syncErr
}

func (e *CloudConnectorEngine) doSync(ctx context.Context, conn *store.CloudConnector) (int, string, error) {
	switch conn.Provider {
	case "aws":
		return syncAWS(ctx, conn, e.db, e.eventDB, e.logger)
	case "azure":
		n, cursor, err := syncAzure(ctx, conn, e.db, e.eventDB, e.logger)
		// Also pull Defender alerts, Entra audit logs, NSG flow logs
		n += syncAzureExtendedLogs(ctx, conn, e.db, e.eventDB, e.logger)
		return n, cursor, err
	case "gcp":
		n, cursor, err := syncGCP(ctx, conn, e.db, e.eventDB, e.logger)
		// Also pull VPC Flow, DNS, and IDS logs (optional — silently skip if not enabled)
		n += syncGCPExtendedLogs(ctx, conn, e.db, e.eventDB, e.logger)
		return n, cursor, err
	default:
		return 0, "", fmt.Errorf("unknown provider: %s", conn.Provider)
	}
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	// G-22: a 403 caused by quota/rate limiting is transient, not a bad
	// credential — retrying (or at least not marking the connector as
	// auth-failed) is the right call.
	for _, transient := range []string{"quota", "ratelimit", "rate limit", "rate_limit", "toomanyrequests", "too many requests", "throttl"} {
		if strings.Contains(msg, transient) {
			return false
		}
	}
	// Match HTTP status codes only as standalone numbers ("status 403",
	// "(401)", "API 403:"), not any "401"/"403" digits inside an ID or URL.
	if authStatusRe.MatchString(msg) {
		return true
	}
	for _, phrase := range []string{"invalid credentials", "auth failed", "unauthorized", "forbidden", "invalid_client", "invalid_grant"} {
		if strings.Contains(msg, phrase) {
			return true
		}
	}
	return false
}

var authStatusRe = regexp.MustCompile(`(?:status[ :]*|api[ :]*|\()(?:401|403)(?:\b|\))`)

// CloudEvent is a normalized cloud event for insertion into the backend events table.
type CloudEvent struct {
	ID        string
	Time      time.Time
	AgentID   string
	Host      string
	OS        string
	EventType string
	Severity  int
	Source    string
	Username  string
	SrcIP     string
	// G-07: destination fields so search / IOC matching can use them
	// (VPC-flow destination, DNS query name) instead of only raw JSON.
	DstIP   string
	DstPort int
	Proto   string
	Raw     json.RawMessage
}

const (
	cloudInsertBatch = 200
	cloudMaxRawBytes = 256 * 1024
)

// cloudRowArgs builds the column values for one event, applying the same
// raw-payload sanitising/size cap the agent ingest path uses (G-06).
func cloudRowArgs(ev CloudEvent) []interface{} {
	nz := func(s string) interface{} {
		if s == "" {
			return nil
		}
		return s
	}
	raw := []byte(ev.Raw)
	// jsonb rejects NUL, both raw and as the \u0000 escape.
	raw = []byte(strings.ToValidUTF8(
		strings.NewReplacer("\x00", "", `\u0000`, "").Replace(string(raw)), ""))
	if len(raw) > cloudMaxRawBytes || !json.Valid(raw) {
		// Too large (or damaged by sanitising): keep a stub rather than
		// dropping the event or storing megabytes.
		stub, _ := json.Marshal(map[string]interface{}{
			"truncated": true, "original_bytes": len(ev.Raw), "source": ev.Source,
		})
		raw = stub
	}
	var dport interface{}
	if ev.DstPort > 0 {
		dport = ev.DstPort
	}
	return []interface{}{
		ev.ID, ev.Time, ev.AgentID, ev.Host, ev.OS, ev.EventType, ev.Severity, ev.Source,
		raw, nz(ev.Username), nz(ev.SrcIP), nz(ev.DstIP), dport, nz(ev.Proto),
	}
}

const cloudInsertCols = "(id, time, agent_id, host, os, event_type, severity, source, raw, user_name, src_ip, dst_ip, dst_port, proto)"

// ingestCloudEvents inserts cloud events in batches (G-06). A failing batch
// is retried row by row so one bad row can't drop its neighbours; failures
// are counted, logged, and returned as an error (callers still get the
// inserted count).
func ingestCloudEvents(ctx context.Context, db *store.DB, events []CloudEvent) (int, error) {
	if db == nil || len(events) == 0 {
		return 0, nil
	}
	const ncols = 14
	inserted, failed := 0, 0
	for start := 0; start < len(events); start += cloudInsertBatch {
		end := start + cloudInsertBatch
		if end > len(events) {
			end = len(events)
		}
		chunk := events[start:end]
		var sb strings.Builder
		args := make([]interface{}, 0, len(chunk)*ncols)
		sb.WriteString("INSERT INTO events " + cloudInsertCols + " VALUES ")
		for i, ev := range chunk {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(")
			for c := 0; c < ncols; c++ {
				if c > 0 {
					sb.WriteString(",")
				}
				fmt.Fprintf(&sb, "$%d", i*ncols+c+1)
			}
			sb.WriteString(")")
			args = append(args, cloudRowArgs(ev)...)
		}
		sb.WriteString(" ON CONFLICT (id, time) DO NOTHING")
		res, err := db.ExecContext(ctx, sb.String(), args...)
		if err == nil {
			n, _ := res.RowsAffected()
			inserted += int(n)
			continue
		}
		// Batch failed: isolate the bad row(s).
		for _, ev := range chunk {
			r, err := db.ExecContext(ctx,
				"INSERT INTO events "+cloudInsertCols+" VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (id, time) DO NOTHING",
				cloudRowArgs(ev)...)
			if err != nil {
				failed++
				slog.Warn("cloud ingest: row insert failed", "id", ev.ID, "type", ev.EventType, "err", err)
				continue
			}
			n, _ := r.RowsAffected()
			inserted += int(n)
		}
	}
	if failed > 0 {
		return inserted, fmt.Errorf("cloud ingest: %d of %d events failed to insert", failed, len(events))
	}
	return inserted, nil
}

// scanAWSCSPM runs the scheduled AWS posture scan, persists the result and the
// CIS-inspired benchmark, and alerts on new critical findings.
func (e *CloudConnectorEngine) scanAWSCSPM(ctx context.Context, id int64) {
	conn, err := e.db.GetCloudConnectorRaw(ctx, id)
	if err != nil {
		return
	}
	scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	creds, err := resolveAWSCreds(scanCtx, conn.Credentials)
	if err != nil {
		e.logger.Warn("cspm: aws credentials unusable", "id", id, "err", err)
		return
	}
	e.logger.Info("cspm: scanning AWS connector", "id", id)
	result, err := RunAWSCSPM(scanCtx, creds, conn.AccountID)
	if err != nil {
		e.logger.Error("cspm: aws scan failed", "id", id, "err", err)
		return
	}
	result.ConnectorID = id
	key := fmt.Sprintf("cspm:aws:%d", id)
	prev, _ := e.db.GetSetting(ctx, key)
	if data, mErr := json.Marshal(result); mErr == nil {
		if sErr := e.db.SetSetting(ctx, key, string(data)); sErr != nil {
			e.logger.Error("cspm: failed to persist aws result", "id", id, "err", sErr)
		}
	}
	awsCIS := AWSCISFromCSPM(result, conn.AccountID, id)
	if data, mErr := json.Marshal(awsCIS); mErr == nil {
		e.db.SetSetting(ctx, fmt.Sprintf("cis:aws:%d", id), string(data))
	}
	if data, mErr := json.Marshal(AWSComplianceFromCIS(awsCIS, id, conn.AccountID)); mErr == nil {
		e.db.SetSetting(ctx, fmt.Sprintf("compliance:aws:%d", id), string(data))
	}
	alertNewCriticalFindings(ctx, e.db, "aws", id, conn.AccountID, prev, result.Findings, e.logger)
	e.logger.Info("cspm: aws scan complete", "id", id, "findings", result.TotalFindings, "critical", result.Critical, "high", result.High)
}
