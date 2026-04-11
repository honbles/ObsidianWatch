package api

import (
	"crypto/tls"
	"os"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

type Server struct {
	cfg         *config.Config
	db          *store.DB
	backendDB   *store.DB
	hub         *Hub
	jwt         *auth.JWTService
	mailer      *notify.Mailer
	logger      *slog.Logger
	http        *http.Server
	cloudEngine  *CloudConnectorEngine
	devopsEngine *DevOpsEngine
	tiEngine    *ThreatIntelEngine
	vtEngine    *VirusTotalEngine
	lrRegistry  *TunnelRegistry
}

func New(cfg *config.Config, db *store.DB, backendDB *store.DB, logger *slog.Logger) *Server {
	jwt := auth.NewJWTService(cfg.Auth.JWTSecret, cfg.Auth.TokenDuration)
	hub := NewHub(db, logger)
	mailer := notify.NewMailer(cfg.SMTP)
	if dbSmtp := smtpConfigFromDB(context.Background(), db); dbSmtp.Host != "" {
		mailer.UpdateConfig(dbSmtp)
	}
	cloudEngine  := NewCloudConnectorEngine(db, backendDB, logger)
	devopsEngine := NewDevOpsEngine(db, backendDB, logger)
	tiEngine := NewThreatIntelEngine(db, logger)
	vtEngine := NewVirusTotalEngine(db, logger)
	lrRegistry := NewTunnelRegistry()
	s := &Server{cfg: cfg, db: db, backendDB: backendDB, hub: hub, jwt: jwt, mailer: mailer, logger: logger, cloudEngine: cloudEngine, devopsEngine: devopsEngine, tiEngine: tiEngine, vtEngine: vtEngine, lrRegistry: lrRegistry}

	mux := http.NewServeMux()

	// Setup wizard (public — needed before login on first run)
	mux.HandleFunc("GET /api/v1/setup/status",    handleSetupStatus(db))
	mux.HandleFunc("POST /api/v1/setup/complete",  handleSetupComplete(db))

	// Public
	mux.HandleFunc("GET /health", handleHealth(db))
	mux.HandleFunc("GET /api/v1/verify-install-key", handleVerifyInstallKey(db))
	mux.HandleFunc("POST /api/v1/agent/register-key", handleAgentRegisterKey(db))
	mux.HandleFunc("POST /auth/login", handleLogin(db, jwt, logger))
	mux.HandleFunc("POST /api/v1/devops/webhook/{id}", handleGitHubWebhook(db, backendDB, logger))

	// Protected
	protected := http.NewServeMux()
	protected.HandleFunc("GET /auth/me",            handleMe)
	protected.HandleFunc("PATCH /auth/password",    handleChangePassword(db))

	// Events
	protected.HandleFunc("GET /api/v1/events",                          handleListEvents(db))
	protected.HandleFunc("GET /api/v1/events/export",                   handleExportEvents(db))
	protected.HandleFunc("GET /api/v1/events/search",                   handleEventSearch(db))
	protected.HandleFunc("GET /api/v1/events/saved-queries",            handleSavedQueries(db))
	protected.HandleFunc("POST /api/v1/events/saved-queries",           handleSavedQueries(db))
	protected.HandleFunc("DELETE /api/v1/events/saved-queries/{id}",   handleSavedQueries(db))
	protected.HandleFunc("GET /api/v1/events/{id}",                     handleGetEvent(db))

	// Agents
	protected.HandleFunc("GET /api/v1/agents",              handleListAgents(db))
	protected.HandleFunc("GET /api/v1/agents/locations",     handleGetAgentLocations(db, s.backendDB))
	protected.HandleFunc("GET /api/v1/agents/{id}",         handleGetAgent(db))
	protected.HandleFunc("PATCH /api/v1/agents/{id}/tamper", handleSetTamperLock(db))
	protected.HandleFunc("POST /api/v1/agents/{id}/regen-key", handleRegenerateKey(db))

	// Alerts
	protected.HandleFunc("GET /api/v1/alerts",                        handleListAlerts(db))
	protected.HandleFunc("POST /api/v1/alerts",                       handleCreateAlert(db, mailer))
	protected.HandleFunc("GET /api/v1/alerts/{id}",                   handleGetAlert(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/acknowledge",     handleAcknowledgeAlert(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/assign",          handleAssignAlert(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/notes",           handleUpdateCaseNotes(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/close-review",    handleCloseWithReview(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/close",           handleCloseAlert(db))

	// Alert Rules
	protected.HandleFunc("GET /api/v1/alert-rules",         handleListAlertRules(db))
	protected.HandleFunc("POST /api/v1/alert-rules",        handleCreateAlertRule(db))
	protected.HandleFunc("PUT /api/v1/alert-rules/{id}",    handleUpdateAlertRule(db))
	protected.HandleFunc("DELETE /api/v1/alert-rules/{id}", handleDeleteAlertRule(db))

	// Users
	protected.HandleFunc("GET /api/v1/users",               handleListUsers(db))
	protected.HandleFunc("POST /api/v1/users",              handleCreateUser(db))
	protected.HandleFunc("DELETE /api/v1/users/{id}",       handleDeleteUser(db))

	// Audit log
	protected.HandleFunc("GET /api/v1/audit-log",           handleListAuditLog(db))

	// Stats & Threat Intel
	protected.HandleFunc("GET /api/v1/stats",               handleStats(db))
	protected.HandleFunc("GET /api/v1/threat-intel",        handleThreatIntel(db))

	// AI Analysis
	protected.HandleFunc("POST /api/v1/ai/analyse", handleAIAnalysis(cfg, db))
	protected.HandleFunc("POST /api/v1/ai/chat",    handleAIChat(cfg, db))

	// Live Response — WebSocket tunnel + session management
	// Agent tunnel endpoint is public (agents auth via X-API-Key header)
	mux.HandleFunc("GET /api/v1/live-response/agent-tunnel", handleAgentTunnel(db, lrRegistry, logger))
	// Analyst-facing endpoints are protected
	protected.HandleFunc("POST /api/v1/live-response/sessions",          handleInitiateSession(db, lrRegistry, logger))
	protected.HandleFunc("GET /api/v1/live-response/sessions",           handleListSessions(db))
	protected.HandleFunc("DELETE /api/v1/live-response/sessions/{token}", handleCloseSession(db))
	protected.HandleFunc("GET /api/v1/live-response/agents",             handleListLRAgents(db, lrRegistry))
	protected.HandleFunc("GET /api/v1/live-response/terminal",           handleSessionTerminal(db, lrRegistry, logger))

	// Cloud Connectors
	protected.HandleFunc("GET /api/v1/cloud-connectors",              handleListCloudConnectors(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors",             handleSaveCloudConnector(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors/test",        handleTestCloudConnector(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors/ai-explain",  handleCSPMAIExplain(cfg, db))
	protected.HandleFunc("DELETE /api/v1/cloud-connectors/{id}",      handleDeleteCloudConnector(db))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/sync",   handleSyncCloudConnector(db, cloudEngine))
	protected.HandleFunc("POST /api/v1/cloud-connectors/{id}/cspm",   handleRunCSPM(db))
	protected.HandleFunc("GET /api/v1/cloud-connectors/{id}/cspm",    handleGetCSPM(db))

	// DevOps Connectors (GitHub, GitLab)
	protected.HandleFunc("GET /api/v1/devops-connectors",               handleListDevOpsConnectors(db))
	protected.HandleFunc("POST /api/v1/devops-connectors",              handleSaveDevOpsConnector(db))
	protected.HandleFunc("POST /api/v1/devops-connectors/test",         handleTestDevOpsConnector(db))
	protected.HandleFunc("DELETE /api/v1/devops-connectors/{id}",       handleDeleteDevOpsConnector(db))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/sync",    handleSyncDevOpsConnector(db, s.devopsEngine))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/commits",  handleListDevOpsCommits(db))
	protected.HandleFunc("GET /api/v1/devops-commits/{sha}", handleGetDevOpsCommit(db))

	// Code scanning
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/code-scan",   handleCodeScan(cfg, db, logger))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/code-scan",    handleGetCodeScanResults(db))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/code-scan/ai", handleCodeScanAI(cfg, db))

	// SAST — static analysis on full repo source
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/sast",     handleSAST(cfg, db, logger))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/sast",      handleGetSASTResults(db))
	protected.HandleFunc("GET /api/v1/devops-connectors/{id}/sast/repos",  handleListSASTRepos(db, logger))
	protected.HandleFunc("POST /api/v1/devops-connectors/{id}/sast/ai",  handleSASTAI(cfg, db))

	protected.HandleFunc("GET /api/v1/agents/{host}/vuln", handleGetVulnScan(db, backendDB))
	protected.HandleFunc("POST /api/v1/agents/{host}/vuln/analyse", handleVulnAIAnalysis(cfg, db, backendDB, logger))
	protected.HandleFunc("GET /api/v1/agents/{host}/vuln/analysis-cache", handleGetVulnAnalysisCache(db))

	// Root Cause Analysis
	protected.HandleFunc("POST /api/v1/agents/{host}/rca",         handleRCAAnalysis(cfg, db, backendDB))
	protected.HandleFunc("GET /api/v1/agents/{host}/rca/cache",    handleGetRCACache(db))
	protected.HandleFunc("GET /api/v1/agents/{host}/rca/context",  handleGetRCAContext(db, backendDB))

	// Detections
	protected.HandleFunc("GET /api/v1/threat-intel/{host}",   handleThreatIntelHost(db))
		protected.HandleFunc("GET /api/v1/threat-graph/{host}", handleThreatGraphHost(db))
	protected.HandleFunc("GET /api/v1/threat-graph-process",   handleThreatGraphProcess(db))
	// New rich graph endpoints
	protected.HandleFunc("GET /api/v1/graph/endpoint/{host}",          handleEndpointGraph(db))
	// File hash / VirusTotal
	protected.HandleFunc("GET /api/v1/file-hashes",            handleListFileHashes(db))
	protected.HandleFunc("GET /api/v1/file-hashes/{hash}",     handleGetFileHash(db))
	protected.HandleFunc("GET /api/v1/graph/endpoint/{host}/processes", handleEndpointProcesses(db))
	protected.HandleFunc("GET /api/v1/graph/cloud",            handleCloudGraph(db))
	// Network device graph route disabled until SNMP integration is built
	// protected.HandleFunc("GET /api/v1/graph/network",       handleNetworkGraph(db))
		protected.HandleFunc("GET /api/v1/detections", handleListDetections(db))
		protected.HandleFunc("GET /api/v1/sast-rules", handleListSASTRules(db))
		protected.HandleFunc("PATCH /api/v1/detections/{id}", handleToggleDetection(db))
	protected.HandleFunc("POST /api/v1/detections/sigma/toggle", handleToggleSigma(db))
	protected.HandleFunc("POST /api/v1/enrichment/isp", handleISPLookup())

		// Threat Intel Sources
		protected.HandleFunc("GET /api/v1/threat-intel-sources",                    handleListThreatIntelSources(db))
		protected.HandleFunc("PATCH /api/v1/threat-intel-sources/{name}",           handleUpdateThreatIntelSource(db, s.tiEngine))
		protected.HandleFunc("POST /api/v1/threat-intel-sources/{name}/sync",       handleTriggerSync(s.tiEngine, db))

	// Agent Builder
	protected.HandleFunc("GET /api/v1/agent-builder/status",                handleAgentBuildStatus())
	protected.HandleFunc("POST /api/v1/agent-builder/build",                 handleAgentBuild(db))
	protected.HandleFunc("GET /api/v1/agent-builder/settings",               handleAgentBuilderSettings(db))
	protected.HandleFunc("POST /api/v1/agent-builder/download",              handleAgentBuilderDownload(db))
	protected.HandleFunc("GET /api/v1/agent-builder/download/{platform}",    handleAgentDownloadCached())

	// Settings — SMTP email notifications
	protected.HandleFunc("GET /api/v1/settings/smtp",      handleGetSMTPSettings(cfg, db))
	// API Keys settings
	protected.HandleFunc("GET /api/v1/settings/api-keys",  handleGetAPIKeys(db))
	protected.HandleFunc("POST /api/v1/settings/api-keys", handleSaveAPIKeys(db))
	protected.HandleFunc("POST /api/v1/settings/smtp",     handleSaveSMTPSettings(db, mailer))
	protected.HandleFunc("POST /api/v1/settings/smtp/test", handleTestSMTP(mailer, db))

	// WebSocket
	protected.HandleFunc("GET /ws/events", hub.ServeWS)

	guard := auth.Middleware(jwt)
	mux.Handle("/api/", guard(protected))
	mux.Handle("/auth/me", guard(protected))
	mux.Handle("/auth/password", guard(protected))
	mux.Handle("/ws/", guard(protected))


	handler := corsMiddleware(cfg.Server.CORSOrigins)(loggingMiddleware(logger)(mux))
	s.http = &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}
	return s
}

func (s *Server) Start(ctx context.Context) error {
	engine := NewAlertEngine(s.db, s.mailer, s.logger)
	go engine.Run(ctx)
	detection := NewDetectionEngine(s.db, s.mailer, s.logger)
	go detection.Run(ctx)
	go s.tiEngine.Run(ctx)
	go s.vtEngine.Run(ctx)
	go s.cloudEngine.Run(ctx)
	go s.devopsEngine.Run(ctx)
	dnsCatWorker := NewDomainCategorizationWorker(s.db, s.logger)
	go dnsCatWorker.Run(ctx)
	go s.hub.Run(ctx)
	// Auto-detect TLS — use cert files if they exist
	certFile := s.cfg.Server.TLSCertFile
	keyFile  := s.cfg.Server.TLSKeyFile
	if certFile == "" { certFile = "/app/certs/server.crt" }
	if keyFile  == "" { keyFile  = "/app/certs/server.key" }

	useTLS := s.cfg.Server.TLSEnabled
	if !useTLS {
		// Auto-enable TLS if cert files exist
		_, certErr := os.Stat(certFile)
		_, keyErr  := os.Stat(keyFile)
		if certErr == nil && keyErr == nil {
			useTLS = true
		}
	}

	if useTLS {
		s.logger.Info("management server starting (TLS)", "addr", s.cfg.Server.ListenAddr,
			"cert", certFile)
		// Configure TLS — support TLS 1.2+ with strong ciphers
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
				if o == "*" || o == origin { allowed = true; break }
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
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
