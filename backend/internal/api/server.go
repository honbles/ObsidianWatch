package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"obsidianwatch/backend/internal/auth"
	"obsidianwatch/backend/internal/config"
	"obsidianwatch/backend/internal/enroll"
	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/pkg/agentid"
)

// Server is the HTTP API server.
type Server struct {
	cfg    *config.Config
	db     *store.DB
	logger *slog.Logger
	http   *http.Server
	stop   context.CancelFunc // stops background refreshers
	renew  http.HandlerFunc
}

// New creates a configured Server ready to call ListenAndServe.
func New(cfg *config.Config, db *store.DB, logger *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, db: db, logger: logger}

	mux := http.NewServeMux()

	// ── Public routes ────────────────────────────────────────────────
	mux.HandleFunc("/health", handleHealth(db))

	// ── Agent routes: authenticated by the agent's own certificate ─────
	// (spec A1-A4). There is no shared API key: an agent enrolls once with
	// an enrollment token at /api/v1/enroll, which is the only route that
	// works without a certificate.
	idCfg := cfg.Auth.AgentIdentity
	ca, created, err := enroll.LoadOrCreateCA(idCfg.CACertFile, idCfg.CAKeyFile)
	if err != nil {
		return nil, err
	}
	agentCA := ca
	if created {
		logger.Warn("agent CA created - back up the key file", "cert", idCfg.CACertFile, "key", idCfg.CAKeyFile)
	}
	if err := db.PublishAgentCA(context.Background(), string(ca.CertPEM)); err != nil {
		logger.Warn("agent CA: could not publish certificate for management", "err", err)
	}
	rev := agentid.NewRevocations(db.RevokedAgentIDs)
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	go rev.Run(ctx, agentid.DefaultRefresh)
	gate := &identityGate{roots: ca.Pool(), revoked: rev, now: time.Now}
	authMiddleware := gate.wrap
	ec := &enrollConfig{ca: ca, certTTL: idCfg.CertTTL, now: time.Now}
	mux.HandleFunc("POST /api/v1/enroll", handleEnroll(db, ec, logger))
	s.renew = handleRenew(db, ec, logger)
	logger.Info("agent identity: certificates required", "cert_ttl", idCfg.CertTTL.String())
	if len(cfg.Auth.APIKeys) > 0 || cfg.Auth.MTLSEnabled {
		logger.Warn("auth.api_keys and auth.mtls_enabled are no longer used: agents authenticate with their own certificate; remove them from server.yaml")
	}

	protected := http.NewServeMux()
	SetTrustedProxies(cfg.Server.TrustedProxies) // M-13
	protected.HandleFunc("POST /api/v1/events", handleIngest(db, cfg.Server.MaxBatchSize, logger))
	protected.HandleFunc("POST /api/v1/agents/location", handleUpdateAgentLocation(db, logger))
	// Fleet-wide queries are never open to an agent certificate.
	protected.HandleFunc("GET /api/v1/events", certOnlyForbidden(handleQueryEvents(db)))
	protected.HandleFunc("GET /api/v1/metrics", certOnlyForbidden(handleMetrics()))
	protected.HandleFunc("GET /api/v1/agents", certOnlyForbidden(handleListAgents(db)))
	protected.HandleFunc("GET /api/v1/agents/{id}", certOnlyForbidden(handleGetAgent(db)))
	protected.HandleFunc("POST /api/v1/enroll/renew", s.renew)
	// Agent calls answered by the management server (live-response tunnel,
	// install-key registration and uninstall check) ride the ingest port:
	// verified here, passed to management with a signed identity.
	if tc := cfg.Tunnel; tc.ManagementURL != "" {
		tp, err := newTunnelProxy(tc.ManagementURL, tc.ManagementCAFile, tc.ManagementServerName, tc.InsecureSkipVerify, os.Getenv("OW_SECRET_KEY"), logger)
		if err != nil {
			return nil, err
		}
		if tp.key == nil {
			logger.Error("tunnel: OW_SECRET_KEY is not set - live response and install-key checks will not work")
		}
		protected.Handle("GET /api/v1/live-response/agent-tunnel", tp)
		protected.Handle("POST /api/v1/agent/register-key", tp)
		protected.Handle("POST /api/v1/verify-install-key", tp)
		logger.Info("tunnel: agent calls pass through to management", "url", tc.ManagementURL)
	}
	// [NET-ROUTES-BEGIN]
	registerNetworkIngestRoutes(protected, db, logger)
	// [NET-ROUTES-END]
	// [APP-ROUTES-BEGIN]
	registerApplicationIngestRoutes(protected, db, logger)
	// [APP-ROUTES-END]

	mux.Handle("/api/", authMiddleware(protected))

	// ── TLS configuration ────────────────────────────────────────────
	// Client certificates are verified against the agent CA when presented
	// (enrollment needs none); each route then requires one.
	var tlsCfg *tls.Config
	if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
		tlsCfg, err = auth.TLSConfig(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.ClientCAs = agentCA.Pool()
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	} else {
		logger.Error("no TLS configured: agents cannot present certificates, so none can connect")
	}

	s.http = &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      loggingMiddleware(logger)(mux),
		TLSConfig:    tlsCfg,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		// Slow-header (slowloris) and idle-connection limits.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	return s, nil
}

// Start begins serving. Blocks until the server stops.
func (s *Server) Start() error {
	s.logger.Info("server starting",
		"addr", s.cfg.Server.ListenAddr,
		"tls", s.cfg.Server.TLSCertFile != "",
		"mtls", s.cfg.Auth.MTLSEnabled,
	)

	if s.http.TLSConfig != nil {
		// TLS config already loaded - use empty strings so ListenAndServeTLS
		// uses the pre-loaded config.
		return s.http.ListenAndServeTLS("", "")
	}
	return s.http.ListenAndServe()
}

// Shutdown gracefully drains connections.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.stop != nil {
		s.stop()
	}
	return s.http.Shutdown(ctx)
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(rw, r)
			logger.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.code,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote", r.RemoteAddr,
			)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	code int
}

// Unwrap lets http.ResponseController reach the connection (WebSocket
// upgrades through the tunnel proxy need Hijack and deadline control).
func (rw *responseWriter) Unwrap() http.ResponseWriter { return rw.ResponseWriter }

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
