package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"obsidianwatch/management/internal/agentid"
	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
	"obsidianwatch/management/internal/telemetry"
)

type Server struct {
	cfg          *config.Config
	db           *store.DB
	backendDB    *store.DB
	hub          *Hub
	jwt          *auth.JWTService
	mailer       *notify.Mailer
	logger       *slog.Logger
	http         *http.Server
	cloudEngine  *CloudConnectorEngine
	devopsEngine *DevOpsEngine
	tiEngine     *ThreatIntelEngine
	vtEngine     *VirusTotalEngine
	lrRegistry   *TunnelRegistry
	tunnelAuth   *tunnelAuth
}

func New(cfg *config.Config, db *store.DB, backendDB *store.DB, logger *slog.Logger) *Server {
	jwt := auth.NewJWTService(cfg.Auth.JWTSecret, cfg.Auth.TokenDuration)
	persistJWTRevocations(context.Background(), db, jwt, logger)
	for _, o := range cfg.Server.CORSOrigins {
		if o == "*" {
			logger.Warn("config: cors_origins contains \"*\"; any website may call this API from a browser. Set cors_origins to the dashboard origin(s) in production.")
			break
		}
	}
	hub := NewHub(db, logger)
	mailer := notify.NewMailer(cfg.SMTP)
	if dbSmtp := smtpConfigFromDB(context.Background(), db); dbSmtp.Host != "" {
		mailer.UpdateConfig(dbSmtp)
	}
	webhooks := notify.NewWebhookDispatcher(db, logger)
	syslogFwd := notify.NewSyslogForwarder(db, logger)
	// P-08/P-09: every new alert fans out to chat/webhook channels and syslog/CEF.
	store.AlertCreatedHook = func(a store.Alert) {
		webhooks.Enqueue(a)
		syslogFwd.Enqueue(a)
	}
	installAlertAnchorLinker(db) // Alert Graph: link every new alert to its entities
	go func() {                  // one-time: make events from before migration 009 usable by the graph
		time.Sleep(30 * time.Second) // let migrations settle
		if n, err := db.BackfillProcessGUIDs(context.Background(), 7); err != nil {
			logger.Warn("graph: process GUID backfill stopped", "err", err, "rows", n)
		} else if n > 0 {
			logger.Info("graph: process GUID backfill done", "rows", n)
		}
	}()
	cloudEngine := NewCloudConnectorEngine(db, backendDB, logger)
	devopsEngine := NewDevOpsEngine(db, backendDB, logger)
	tiEngine := NewThreatIntelEngine(db, logger)
	vtEngine := NewVirusTotalEngine(db, logger)
	lrRegistry := NewTunnelRegistry()
	s := &Server{cfg: cfg, db: db, backendDB: backendDB, hub: hub, jwt: jwt, mailer: mailer, logger: logger, cloudEngine: cloudEngine, devopsEngine: devopsEngine, tiEngine: tiEngine, vtEngine: vtEngine, lrRegistry: lrRegistry}

	mux := http.NewServeMux()

	// Setup wizard (public - needed before login on first run)
	mux.HandleFunc("GET /api/v1/setup/status", handleSetupStatus(db, jwt))
	mux.HandleFunc("POST /api/v1/setup/complete", handleSetupComplete(db, jwt))

	// Public
	mux.HandleFunc("GET /health", handleHealth(db))
	mux.HandleFunc("POST /auth/login", handleLogin(db, jwt, logger))
	mux.HandleFunc("POST /api/v1/devops/webhook/{id}", handleGitHubWebhook(db, backendDB, logger))
	mux.HandleFunc("POST /api/v1/devops/webhook-gitlab/{id}", handleGitLabWebhook(db, backendDB, logger))
	mux.HandleFunc("POST /api/v1/devops/webhook-azuredevops/{id}", handleADOWebhook(db, backendDB, logger))

	// Protected
	protected := http.NewServeMux()
	// Shared rule contract API (foundation)
	protected.HandleFunc("GET /api/v1/rules/meta", handleRuleMeta())
	protected.HandleFunc("GET /api/v1/rules/settings", handleListRuleSettings(db))
	protected.HandleFunc("PUT /api/v1/rules/settings", adminOnly(handlePutRuleSetting(db)))
	protected.HandleFunc("GET /api/v1/prevention", handleGetPrevention(db))
	protected.HandleFunc("PUT /api/v1/prevention", adminOnly(handlePutPrevention(db)))
	// [NET-ROUTES-BEGIN]
	registerNetRoutes(protected, db, backendDB)
	// [NET-ROUTES-END]
	// [APP-ROUTES-BEGIN]
	registerAppRoutes(protected, db, backendDB)
	// [APP-ROUTES-END]
	protected.HandleFunc("GET /auth/me", handleMe)
	protected.HandleFunc("POST /auth/logout", handleLogout(db, jwt))
	protected.HandleFunc("POST /auth/ws-ticket", handleWSTicket)
	protected.HandleFunc("PATCH /auth/password", handleChangePassword(db, jwt))

	// Events
	protected.HandleFunc("GET /api/v1/events", handleListEvents(db))
	protected.HandleFunc("GET /api/v1/events/export", handleExportEvents(db))
	protected.HandleFunc("GET /api/v1/events/search", handleEventSearch(db))
	protected.HandleFunc("GET /api/v1/events/summary", handleEventSummary(db))
	protected.HandleFunc("GET /api/v1/events/saved-queries", handleSavedQueries(db))
	protected.HandleFunc("POST /api/v1/events/saved-queries", handleSavedQueries(db))
	protected.HandleFunc("DELETE /api/v1/events/saved-queries/{id}", handleSavedQueries(db))
	protected.HandleFunc("PUT /api/v1/events/saved-queries/{id}/schedule", handleScheduleSavedQuery(db))
	protected.HandleFunc("GET /api/v1/events/{id}", handleGetEvent(db))

	// Agents
	protected.HandleFunc("GET /api/v1/agents", handleListAgents(db))
	protected.HandleFunc("GET /api/v1/agents/locations", handleGetAgentLocations(db, s.backendDB))
	protected.HandleFunc("GET /api/v1/agents/{id}", handleGetAgent(db))
	protected.HandleFunc("DELETE /api/v1/agents/{id}", adminOnly(handleDeleteAgent(db, lrRegistry, logger)))
	protected.HandleFunc("PATCH /api/v1/agents/{id}/tamper", adminOnly(handleSetTamperLock(db)))
	protected.HandleFunc("POST /api/v1/agents/{id}/regen-key", adminOnly(handleRegenerateKey(db)))

	// Alerts
	protected.HandleFunc("GET /api/v1/alerts", handleListAlerts(db))
	protected.HandleFunc("POST /api/v1/alerts", handleCreateAlert(db, mailer))
	protected.HandleFunc("GET /api/v1/alerts/{id}", handleGetAlert(db))
	protected.HandleFunc("GET /api/v1/alerts/{id}/graph", handleAlertGraph(db))
	protected.HandleFunc("POST /api/v1/alerts/{id}/graph/analyse", handleAlertGraphAnalyse(cfg, db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/acknowledge", handleAcknowledgeAlert(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/assign", handleAssignAlert(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/notes", handleUpdateCaseNotes(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/close-review", handleCloseWithReview(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/close", handleCloseAlert(db))
	protected.HandleFunc("GET /api/v1/alerts/{id}/false-positive", handleFalsePositivePreview(db))
	protected.HandleFunc("POST /api/v1/alerts/{id}/false-positive", handleFalsePositive(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/reopen", handleReopenAlert(db))
	protected.HandleFunc("POST /api/v1/alerts/bulk", handleBulkAlerts(db))
	protected.HandleFunc("GET /api/v1/alerts/sla", handleAlertSLA(db))

	// Alert Rules
	protected.HandleFunc("GET /api/v1/alert-rules", handleListAlertRules(db))
	protected.HandleFunc("POST /api/v1/alert-rules/test", handleTestAlertRule(db))
	protected.HandleFunc("POST /api/v1/alert-rules", handleCreateAlertRule(db))
	protected.HandleFunc("PUT /api/v1/alert-rules/{id}", handleUpdateAlertRule(db))
	protected.HandleFunc("DELETE /api/v1/alert-rules/{id}", handleDeleteAlertRule(db))

	// Users
	protected.HandleFunc("GET /api/v1/users", adminOnly(handleListUsers(db)))
	// Assignable people for alert/case pickers: id, name and role only, for any
	// signed-in role. The full user list (login times, password state) is admin-only (spec F3).
	protected.HandleFunc("GET /api/v1/assignees", handleListAssignees(db))
	protected.HandleFunc("POST /api/v1/users", handleCreateUser(db))
	protected.HandleFunc("DELETE /api/v1/users/{id}", handleDeleteUser(db, jwt))

	// Audit log
	protected.HandleFunc("GET /api/v1/audit-log", handleListAuditLog(db))

	// Stats & Threat Intel
	protected.HandleFunc("GET /api/v1/suppressions", handleListSuppressions(db))
	protected.HandleFunc("POST /api/v1/suppressions", handleCreateSuppression(db))
	protected.HandleFunc("GET /api/v1/suppressions/preview", handlePreviewSuppression())
	protected.HandleFunc("PUT /api/v1/suppressions/{id}", handleUpdateSuppression(db))
	protected.HandleFunc("DELETE /api/v1/suppressions/{id}", handleDeleteSuppression(db))
	protected.HandleFunc("GET /api/v1/stats", cachedGET(20*time.Second, handleStats(db)))
	protected.HandleFunc("GET /api/v1/threat-intel", handleThreatIntel(db))
	protected.HandleFunc("GET /api/v1/enrich/ip/{ip}", handleEnrichIP(db, newIPEnricher()))

	// AI Analysis
	protected.HandleFunc("POST /api/v1/ai/analyse", aiLimited(handleAIAnalysis(cfg, db)))
	protected.HandleFunc("POST /api/v1/ai/chat", aiLimited(handleAIChat(cfg, db)))

	// Live Response - WebSocket tunnel + session management
	// Agent tunnel endpoint is public (agents auth via X-API-Key header)
	// A2/A3: agent tunnels authenticate with the agent certificate (agent
	// listener) or, until enforced, the fleet key.
	idDB := backendDB
	if idDB == nil {
		idDB = db
	}
	s.tunnelAuth = &tunnelAuth{
		rev:    agentid.NewRevocations(idDB.RevokedAgentIDs),
		now:    time.Now,
		fwdKey: tunnelIdentityKey(os.Getenv("OW_SECRET_KEY")),
	}
	if s.tunnelAuth.fwdKey == nil {
		logger.Error("OW_SECRET_KEY is not set: agents cannot reach live response or install-key checks")
	}
	s.tunnelAuth.rev.OnLoad(func(rv map[string]bool) { lrRegistry.closeRevokedTunnels(rv, logger) })
	tunnelHandler := handleAgentTunnel(db, lrRegistry, logger, s.tunnelAuth)
	mux.HandleFunc("GET /api/v1/live-response/agent-tunnel", tunnelHandler)
	// Install-key registration and uninstall check, called by agents through
	// the ingest backend with their certificate identity.
	mux.HandleFunc("POST /api/v1/verify-install-key", handleVerifyInstallKey(db, s.tunnelAuth))
	mux.HandleFunc("POST /api/v1/agent/register-key", handleAgentRegisterKey(db, s.tunnelAuth))
	mux.HandleFunc("GET /api/v1/agent/prevention", handleAgentPrevention(db, s.tunnelAuth, logger))
	// Agent enrollment administration (A1, A4). Admin only.
	protected.HandleFunc("GET /api/v1/enrollment-tokens", adminOnly(handleListEnrollmentTokens(idDB)))
	protected.HandleFunc("POST /api/v1/enrollment-tokens", adminOnly(handleCreateEnrollmentToken(idDB)))
	protected.HandleFunc("DELETE /api/v1/enrollment-tokens/{id}", adminOnly(handleRevokeEnrollmentToken(idDB)))
	protected.HandleFunc("GET /api/v1/agent-identities", adminOnly(handleListAgentIdentities(idDB)))
	protected.HandleFunc("POST /api/v1/agent-identities/{id}/revoke", adminOnly(handleRevokeAgentIdentity(idDB, lrRegistry, s.tunnelAuth.rev, logger)))
	// Analyst-facing endpoints are protected
	protected.HandleFunc("POST /api/v1/live-response/sessions", adminOnly(handleInitiateSession(db, lrRegistry, logger)))
	protected.HandleFunc("GET /api/v1/live-response/sessions", handleListSessions(db))
	protected.HandleFunc("DELETE /api/v1/live-response/sessions/{token}", adminOnly(handleCloseSession(db)))
	protected.HandleFunc("GET /api/v1/live-response/agents", handleListLRAgents(db, lrRegistry))
	protected.HandleFunc("GET /api/v1/live-response/terminal", handleSessionTerminal(db, lrRegistry, logger))

	// One-click response (isolate/release, kill, quarantine) and threat hunting at scale.
	protected.HandleFunc("POST /api/v1/agents/{id}/actions", adminOnly(handleAgentAction(db, lrRegistry, logger)))
	protected.HandleFunc("GET /api/v1/agents/{id}/response", handleAgentResponseState(db, lrRegistry))
	protected.HandleFunc("GET /api/v1/agents/{id}/protection", handleAgentProtection(db, lrRegistry))
	protected.HandleFunc("GET /api/v1/agents/{id}/processes", adminOnly(handleAgentProcesses(db, lrRegistry)))
	protected.HandleFunc("GET /api/v1/response/isolated", handleIsolatedAgents(db))
	protected.HandleFunc("GET /api/v1/response/actions", handleResponseActions(db))
	protected.HandleFunc("GET /api/v1/response/actions/{id}/file", adminOnly(handleCollectedFile(db)))
	protected.HandleFunc("POST /api/v1/hunt/live", adminOnly(handleStartFleetHunt(db, lrRegistry, logger)))
	protected.HandleFunc("GET /api/v1/hunt/live", handleListFleetHunts(db))
	protected.HandleFunc("GET /api/v1/hunt/live/{id}", handleGetFleetHunt(db))
	protected.HandleFunc("GET /api/v1/hunt/live/{id}/csv", handleFleetHuntCSV(db))
	protected.HandleFunc("GET /api/v1/hunt/history", handleHistoryHunt(db))
	protected.HandleFunc("GET /api/v1/hunt/library", handleHuntLibrary())

	// Cloud Connectors
	protected.HandleFunc("GET /api/v1/cloud-connectors", handleListCloudConnectors(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors", adminOnly(handleSaveCloudConnector(db)))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/aws-org-import", adminOnly(handleAWSOrgImport(db)))
	protected.HandleFunc("POST /api/v1/cloud-connectors/test", adminOnly(handleTestCloudConnector(db)))
	protected.HandleFunc("POST /api/v1/cloud-connectors/ai-explain", handleCSPMAIExplain(cfg, db))
	protected.HandleFunc("DELETE /api/v1/cloud-connectors/{id}", adminOnly(handleDeleteCloudConnector(db)))
	protected.HandleFunc("GET /api/v1/cloud-connectors/{id}/sources", handleConnectorSources())
	protected.HandleFunc("GET /api/v1/prevalence", handlePrevalence(db))
	protected.HandleFunc("GET /api/v1/log-sources", handleLogSources(db))
	protected.HandleFunc("GET /api/v1/jobs/{id}", handleGetJob())
	protected.HandleFunc("GET /api/v1/identity/timeline", handleIdentityTimeline(db))
	protected.HandleFunc("GET /api/v1/identity/aliases", handleIdentityAliases(db))
	protected.HandleFunc("PUT /api/v1/identity/aliases", handleIdentityAliases(db))
	protected.HandleFunc("POST /api/v1/events/nl-query", aiLimited(handleNLSearch(cfg, db)))
	protected.HandleFunc("GET /api/v1/incidents", handleIncidents(db))
	protected.HandleFunc("PATCH /api/v1/incidents/{id}", handleIncidentUpdate(db))
	protected.HandleFunc("GET /api/v1/coverage/attack", handleAttackCoverage(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/sync", handleSyncCloudConnector(db, cloudEngine))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/cspm", asyncJob(handleRunCSPM(db)))
	protected.HandleFunc("GET /api/v1/cloud-connectors/{id}/cspm", handleGetCSPM(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/cis", asyncJob(handleRunCIS(db)))
	protected.HandleFunc("GET /api/v1/cloud-connectors/{id}/cis", handleGetCIS(db))
	protected.HandleFunc("GET /api/v1/cloud-connectors/{id}/compliance", handleGetCompliance(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/compliance", asyncJob(handleRunCompliance(db)))
	// GCP Suppression rules
	protected.HandleFunc("GET /api/v1/cloud-connectors/suppress", handleListGCPSuppressRules(cloudEngine.Suppressor()))
	protected.HandleFunc("POST /api/v1/cloud-connectors/suppress", handleCreateGCPSuppressRule(cloudEngine.Suppressor()))
	protected.HandleFunc("DELETE /api/v1/cloud-connectors/suppress/{id}", handleDeleteGCPSuppressRule(cloudEngine.Suppressor()))
	protected.HandleFunc("GET /api/v1/cloud-connectors/suppress/azure", handleListAzureSuppressRules(cloudEngine.AzureSuppressor()))
	protected.HandleFunc("POST /api/v1/cloud-connectors/suppress/azure", handleCreateAzureSuppressRule(cloudEngine.AzureSuppressor()))
	protected.HandleFunc("DELETE /api/v1/cloud-connectors/suppress/azure/{id}", handleDeleteAzureSuppressRule(cloudEngine.AzureSuppressor()))
	protected.HandleFunc("GET /api/v1/cloud-connectors/suppress/aws", handleListAWSSuppressRules(activeAWSSuppressor))
	protected.HandleFunc("POST /api/v1/cloud-connectors/suppress/aws", adminOnly(handleCreateAWSSuppressRule(activeAWSSuppressor)))
	protected.HandleFunc("DELETE /api/v1/cloud-connectors/suppress/aws/{id}", adminOnly(handleDeleteAWSSuppressRule(activeAWSSuppressor)))
	// Asset Inventory (CMDB) - GCP and Azure
	protected.HandleFunc("GET /api/v1/cloud-connectors/{id}/assets", handleCloudAssets(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/assets", handleRunCloudAssets(db, logger))
	protected.HandleFunc("GET /api/v1/cloud-connectors/{id}/blast", handleGetBlastRadius(db))
	protected.HandleFunc("GET /api/v1/cloud-connectors/{id}/cspm/history", handleCSPMHistory(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/blast", asyncJob(handleRunBlastRadius(db)))

	// DevOps Connectors (GitHub, GitLab)
	protected.HandleFunc("GET /api/v1/devops-connectors", handleListDevOpsConnectors(db))
	protected.HandleFunc("POST /api/v1/devops-connectors", adminOnly(handleSaveDevOpsConnector(db)))
	protected.HandleFunc("POST /api/v1/devops-connectors/test", adminOnly(handleTestDevOpsConnector(db)))
	protected.HandleFunc("DELETE /api/v1/devops-connectors/{id}", adminOnly(handleDeleteDevOpsConnector(db)))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/sync", handleSyncDevOpsConnector(db, s.devopsEngine))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/commits", handleListDevOpsCommits(db))
	protected.HandleFunc("GET /api/v1/devops-commits/{sha}", handleGetDevOpsCommit(db))

	// Code scanning
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/code-scan", handleCodeScan(cfg, db, logger))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/code-scan", handleGetCodeScanResults(db))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/code-scan/ai", handleCodeScanAI(cfg, db))

	// SAST - static analysis on full repo source
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/posture", handleGetDevOpsPosture(db))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/posture", asyncJob(handleDevOpsPosture(db)))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/sast", asyncJob(handleSAST(cfg, db, logger)))
	protected.HandleFunc("GET /api/v1/findings", handleUnifiedFindings(db))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/sast", handleGetSASTResults(db))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/sast/repos", handleListSASTRepos(db, logger))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/sast/sbom", handleSASTSBOM(db))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/sast/branches", handleListSASTBranches(db))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/sast/coverage", handleSASTCoverage(db, logger))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/sast/issues", handleCreateIssues(db))
	// Code step 3: scan automation (push, schedule, PR checks).
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/scan-policy", handleGetCodeScanPolicy(db))
	protected.HandleFunc("PUT /api/v1/devops-connectors/{id}/scan-policy", adminOnly(handlePutCodeScanPolicy(db)))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/scan-jobs", handleListCodeScanJobs(db))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/scan-jobs", adminOnly(handleEnqueueCodeScan(db, logger)))
	protected.HandleFunc("GET /api/v1/scan-jobs/{job}", handleGetCodeScanJob(db))
	// Code step 4: runtime reachability.
	protected.HandleFunc("GET /api/v1/runtime-packages", handleRuntimePackages(db))
	// Code step 5: fix suggestions and triage.
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/sast/fix", handleSuggestFix(cfg, db))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/findings/triage", handleTriageFinding(db))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/triage-rules", handleListTriageRules(db))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/triage-rules", adminOnly(handleCreateTriageRule(db)))
	protected.HandleFunc("DELETE /api/v1/devops-connectors/{id}/triage-rules/{rule}", adminOnly(handleDeleteTriageRule(db)))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/sast/ai", handleSASTAI(cfg, db))

	protected.HandleFunc("GET /api/v1/agents/{host}/vuln", handleGetVulnScan(cfg, db, backendDB))
	protected.HandleFunc("POST /api/v1/agents/{host}/vuln/osv", asyncJob(handleEndpointOSV(db, backendDB)))
	protected.HandleFunc("GET /api/v1/agents/{host}/compliance", handleEndpointCompliance(db, backendDB))
	protected.HandleFunc("GET /api/v1/inventory/search", handleInventorySearch(db, backendDB))
	protected.HandleFunc("GET /api/v1/hosts/meta", handleListHostMeta(db))
	protected.HandleFunc("PUT /api/v1/hosts/{host}/meta", adminOnly(handleSetHostMeta(db)))
	protected.HandleFunc("POST /api/v1/agents/{host}/vuln/analyse", aiLimited(handleVulnAIAnalysis(cfg, db, backendDB, logger)))
	protected.HandleFunc("GET /api/v1/agents/{host}/vuln/analysis-cache", handleGetVulnAnalysisCache(db))

	// Root Cause Analysis
	protected.HandleFunc("POST /api/v1/agents/{host}/rca", aiLimited(handleRCAAnalysis(cfg, db, backendDB)))
	protected.HandleFunc("GET /api/v1/agents/{host}/rca/cache", handleGetRCACache(db))
	protected.HandleFunc("GET /api/v1/agents/{host}/rca/context", handleGetRCAContext(db, backendDB))

	// Detections
	protected.HandleFunc("GET /api/v1/threat-intel/{host}", handleThreatIntelHost(db))
	protected.HandleFunc("GET /api/v1/threat-graph/{host}", handleThreatGraphHost(db))
	protected.HandleFunc("GET /api/v1/threat-graph-process", handleThreatGraphProcess(db))
	// New rich graph endpoints
	protected.HandleFunc("GET /api/v1/graph/endpoint/{host}", handleEndpointGraph(db))
	// File hash / VirusTotal
	protected.HandleFunc("GET /api/v1/file-hashes", handleListFileHashes(db))
	protected.HandleFunc("GET /api/v1/file-hashes/{hash}", handleGetFileHash(db))
	protected.HandleFunc("GET /api/v1/graph/endpoint/{host}/processes", handleEndpointProcesses(db))
	protected.HandleFunc("GET /api/v1/graph/cloud", handleCloudGraph(db))
	// Network device graph route disabled until SNMP integration is built
	// protected.HandleFunc("GET /api/v1/graph/network",       handleNetworkGraph(db))
	protected.HandleFunc("GET /api/v1/detections", handleListDetections(db))
	protected.HandleFunc("GET /api/v1/sast-rules", handleListSASTRules(db))
	protected.HandleFunc("PATCH /api/v1/detections/{id}", adminOnly(handleToggleDetection(db)))
	protected.HandleFunc("POST /api/v1/detections/{id}/backtest", adminOnly(handleBacktestRule(db)))
	protected.HandleFunc("GET /api/v1/detections/sigma/rules", handleListSigmaRules(db))
	protected.HandleFunc("PATCH /api/v1/detections/sigma/rules/{id}", adminOnly(handleSetSigmaRule(db)))
	protected.HandleFunc("POST /api/v1/detections/sigma/toggle", adminOnly(handleToggleSigma(db)))
	protected.HandleFunc("POST /api/v1/enrichment/isp", handleISPLookup())

	// Threat Intel Sources
	protected.HandleFunc("GET /api/v1/threat-intel-sources", handleListThreatIntelSources(db))
	protected.HandleFunc("GET /api/v1/iocs/manual", handleListManualIOCs(db))
	protected.HandleFunc("POST /api/v1/iocs/manual", adminOnly(handleAddManualIOC(db, s.tiEngine)))
	protected.HandleFunc("DELETE /api/v1/iocs/manual/{id}", adminOnly(handleDeleteManualIOC(db)))
	protected.HandleFunc("PATCH /api/v1/threat-intel-sources/{name}", adminOnly(handleUpdateThreatIntelSource(db, s.tiEngine)))
	protected.HandleFunc("POST /api/v1/threat-intel-sources/sigma/pin-seen", adminOnly(handleSigmaPinSeen(db)))
	protected.HandleFunc("POST /api/v1/threat-intel-sources/{name}/sync", handleTriggerSync(s.tiEngine, db))

	// Agent Builder
	protected.HandleFunc("GET /api/v1/agent-builder/status", handleAgentBuildStatus())
	protected.HandleFunc("POST /api/v1/agent-builder/build", adminOnly(handleAgentBuild(db, idDB)))
	protected.HandleFunc("GET /api/v1/agent-builder/settings", adminOnly(handleAgentBuilderSettings(db)))
	protected.HandleFunc("POST /api/v1/agent-builder/download", adminOnly(handleAgentBuilderDownload(db, idDB)))
	protected.HandleFunc("GET /api/v1/agent-builder/download/{platform}", adminOnly(handleAgentDownloadCached()))

	// Settings - SMTP email notifications
	protected.HandleFunc("GET /api/v1/settings/smtp", handleGetSMTPSettings(cfg, db))
	// API Keys settings
	protected.HandleFunc("GET /api/v1/settings/api-keys", handleGetAPIKeys(db))
	protected.HandleFunc("POST /api/v1/settings/api-keys", adminOnly(handleSaveAPIKeys(db)))
	protected.HandleFunc("GET /api/v1/settings/webhooks", handleGetWebhooks(db))
	protected.HandleFunc("POST /api/v1/settings/webhooks", adminOnly(handleSaveWebhooks(db, webhooks)))
	protected.HandleFunc("POST /api/v1/settings/webhooks/test", adminOnly(handleTestWebhook(db, webhooks)))
	protected.HandleFunc("GET /api/v1/settings/syslog", handleGetSyslog(db))
	protected.HandleFunc("POST /api/v1/settings/syslog", adminOnly(handleSaveSyslog(db, syslogFwd)))
	protected.HandleFunc("POST /api/v1/settings/syslog/test", adminOnly(handleTestSyslog(syslogFwd)))
	protected.HandleFunc("POST /api/v1/settings/smtp", adminOnly(handleSaveSMTPSettings(db, mailer)))
	protected.HandleFunc("POST /api/v1/settings/smtp/test", adminOnly(handleTestSMTP(mailer, db)))

	// WebSocket
	protected.HandleFunc("GET /ws/events", hub.ServeWS)

	// Every authenticated request passes the password-change gate (spec F2):
	// until the initial password is changed only /auth/password, /auth/me and
	// /auth/logout answer.
	pwGate := newPasswordGate(storePasswordLookup(db.GetUserByID))
	jwtGuard := auth.Middleware(jwt)
	guard := func(h http.Handler) http.Handler { return jwtGuard(pwGate.wrap(h)) }
	auditedProtected := readOnlyRole(auditMutations(db, protected))
	mux.Handle("/api/", guard(auditedProtected))
	mux.Handle("/auth/me", guard(auditedProtected))
	mux.Handle("/auth/password", guard(auditedProtected))
	mux.Handle("/auth/logout", guard(auditedProtected))
	mux.Handle("/auth/ws-ticket", guard(readOnlyRole(protected))) // not audited: one per socket open
	mux.Handle("/ws/", guard(readOnlyRole(protected)))

	// Route template for traces: the outer mux, then the protected mux for /api/ and /auth/ paths.
	route := func(r *http.Request) string {
		_, p := mux.Handler(r)
		switch p {
		case "/api/", "/auth/me", "/auth/password", "/auth/logout", "/auth/ws-ticket", "/ws/":
			_, p2 := protected.Handler(r)
			if p2 == "" {
				return "(unmatched)"
			}
			p = p2
		}
		return telemetry.RouteOf(p)
	}
	handler := securityHeaders(corsMiddleware(cfg.Server.CORSOrigins)(loggingMiddleware(logger)(telemetry.Middleware(route)(limitRequestBody(maxRequestBody)(mux)))))
	s.http = &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		// Slow-header (slowloris) and idle-connection limits.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return s
}

func (s *Server) Start(ctx context.Context) error {
	refreshAIModels(ctx, s.db)
	// E1: end the wait for hosts that never came back, even if nobody opens the hunt.
	go func() {
		tk := time.NewTicker(5 * time.Minute)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				_ = s.db.ExpireQueuedHunts(ctx)
			}
		}
	}()
	// A4: revocations and the agent CA are re-read well inside 60 s.
	go s.tunnelAuth.rev.Run(ctx, agentid.DefaultRefresh)
	engine := NewAlertEngine(s.db, s.mailer, s.logger)
	go engine.Run(ctx)
	detection := NewDetectionEngine(s.db, s.mailer, s.logger)
	go detection.Run(ctx)
	go s.tiEngine.Run(ctx)
	go s.vtEngine.Run(ctx)
	go s.cloudEngine.Run(ctx)
	go s.devopsEngine.Run(ctx)
	go NewCodeAutomation(s.cfg, s.db, s.logger).Run(ctx)
	go NewRuntimeIndexer(s.db, s.backendDB, s.logger).Run(ctx)
	go NewDeployedCommitWatcher(s.db, s.backendDB, s.logger).Run(ctx)
	dnsCatWorker := NewDomainCategorizationWorker(s.db, s.logger)
	go dnsCatWorker.Run(ctx)
	go s.hub.Run(ctx)
	// D-11: alert on silent agents, stalled engines, and rising queue
	// depth/drops reported in agents' own health events.
	agentHealth := NewAgentHealthEngine(s.db, s.logger)
	go agentHealth.Run(ctx)
	// P-07: scheduled saved searches.
	go NewScheduledSearchEngine(s.db, s.logger).Run(ctx)
	// Auto-detect TLS - use cert files if they exist
	certFile := s.cfg.Server.TLSCertFile
	keyFile := s.cfg.Server.TLSKeyFile
	if certFile == "" {
		certFile = "/app/certs/server.crt"
	}
	if keyFile == "" {
		keyFile = "/app/certs/server.key"
	}

	useTLS := s.cfg.Server.TLSEnabled
	if !useTLS {
		// Auto-enable TLS if cert files exist
		_, certErr := os.Stat(certFile)
		_, keyErr := os.Stat(keyFile)
		if certErr == nil && keyErr == nil {
			useTLS = true
		}
	}

	if useTLS {
		s.logger.Info("management server starting (TLS)", "addr", s.cfg.Server.ListenAddr,
			"cert", certFile)
		// Configure TLS - support TLS 1.2+ with strong ciphers
		s.http.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_AES_128_GCM_SHA256,
			},
		}
		return s.http.ListenAndServeTLS(certFile, keyFile)
	}
	s.logger.Info("management server starting (HTTP)", "addr", s.cfg.Server.ListenAddr)
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := false
			for _, o := range origins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			w.Header().Add("Vary", "Origin") // responses differ by Origin; keep shared caches correct
			if allowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			// Always respond to OPTIONS before hitting any auth middleware
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("Upgrade"), "websocket") {
				logger.Info("ws", "path", r.URL.Path, "remote", r.RemoteAddr)
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, code: 200}
			next.ServeHTTP(rw, r)
			logger.Info("http", "method", r.Method, "path", r.URL.Path, "status", rw.code, "ms", time.Since(start).Milliseconds())
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// maxRequestBody caps every request body (H-07). Many handlers decode JSON
// straight from r.Body with no limit of their own, so a single oversized POST
// could exhaust memory. 8 MiB is far above any legitimate API payload here.
const maxRequestBody = 8 << 20

func limitRequestBody(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.Body != http.NoBody && !strings.Contains(r.Header.Get("Upgrade"), "websocket") {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// securityHeaders adds baseline hardening headers to every response, and marks
// API responses uncacheable so alert and event data never lingers in a shared
// cache or browser history.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
