package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
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

	// ── Agent ingest + query routes (auth required) ──────────────────
	// Fleet API key: the DB key takes priority - if setup has run, the DB key
	// is the real one. Only fall back to the YAML key if the DB has nothing
	// yet (fresh install before the setup wizard has been completed).
	validKeys := cfg.Auth.APIKeys
	if dbKey := db.GetAgentAPIKey(context.Background()); dbKey != "" {
		validKeys = []string{dbKey}
		logger.Info("auth: using agent API key from database")
	} else {
		logger.Info("auth: no DB key yet - using key(s) from server.yaml")
	}
	keyAuth := auth.APIKeyMiddleware(validKeys)

	idCfg := cfg.Auth.AgentIdentity
	var authMiddleware func(http.Handler) http.Handler
	var agentCA *enroll.CA
	if idCfg.Mode == IdentityLegacy {
		if cfg.Auth.MTLSEnabled {
			authMiddleware = auth.MTLSMiddleware
		} else {
			authMiddleware = keyAuth
		}
	} else {
		// A1-A4: per-agent certificates from the agent CA.
		ca, created, err := enroll.LoadOrCreateCA(idCfg.CACertFile, idCfg.CAKeyFile)
		if err != nil {
			return nil, err
		}
		agentCA = ca
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
		gate := &identityGate{
			mode: idCfg.Mode, roots: ca.Pool(), revoked: rev, keyAuth: keyAuth,
			legacyCA: cfg.Auth.MTLSEnabled, now: time.Now,
		}
		authMiddleware = gate.wrap
		ec := &enrollConfig{
			ca: ca, certTTL: idCfg.CertTTL, fleetKeys: validKeys,
			allowFleetKey: idCfg.AllowFleetKeyEnrollment, now: time.Now,
		}
		// The enrollment endpoint is the only one reachable without a
		// certificate once identity is enforced.
		mux.HandleFunc("POST /api/v1/enroll", handleEnroll(db, ec, logger))
		s.renew = handleRenew(db, ec, logger)
		logger.Info("agent identity enabled", "mode", idCfg.Mode, "cert_ttl", idCfg.CertTTL.String(),
			"fleet_key_enrollment", idCfg.AllowFleetKeyEnrollment)
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
	if s.renew != nil {
		protected.HandleFunc("POST /api/v1/enroll/renew", s.renew)
	}
	// [NET-ROUTES-BEGIN]
	registerNetworkIngestRoutes(protected, db, logger)
	// [NET-ROUTES-END]
	// [APP-ROUTES-BEGIN]
	registerApplicationIngestRoutes(protected, db, logger)
	// [APP-ROUTES-END]

	mux.Handle("/api/", authMiddleware(protected))

	// ── TLS configuration ────────────────────────────────────────────
	var tlsCfg *tls.Config
	var err error

	if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
		if cfg.Auth.MTLSEnabled && cfg.Server.TLSCAFile != "" {
			caPool, err := auth.LoadCA(cfg.Server.TLSCAFile)
			if err != nil {
				return nil, err
			}
			tlsCfg, err = auth.MTLSConfig(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile, caPool)
			if err != nil {
				return nil, err
			}
			if agentCA != nil {
				// Enrollment must work without a certificate: verify when
				// given, enforce per route at the HTTP layer.
				caPool.AddCert(agentCA.Cert)
				tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
			}
		} else {
			tlsCfg, err = auth.TLSConfig(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
			if err == nil && agentCA != nil {
				tlsCfg.ClientCAs = agentCA.Pool()
				tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
			}
		}
		if err != nil {
			return nil, err
		}
	} else if agentCA != nil {
		logger.Warn("agent identity: no TLS configured, certificates cannot be presented; only the fleet key works")
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
