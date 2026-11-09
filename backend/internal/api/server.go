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
	"obsidianwatch/backend/internal/store"
)

// Server is the HTTP API server.
type Server struct {
	cfg    *config.Config
	db     *store.DB
	logger *slog.Logger
	http   *http.Server
}

// New creates a configured Server ready to call ListenAndServe.
func New(cfg *config.Config, db *store.DB, logger *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, db: db, logger: logger}

	mux := http.NewServeMux()

	// ── Public routes ────────────────────────────────────────────────
	mux.HandleFunc("/health", handleHealth(db))

	// ── Agent ingest + query routes (auth required) ──────────────────
	var authMiddleware func(http.Handler) http.Handler
	if cfg.Auth.MTLSEnabled {
		authMiddleware = auth.MTLSMiddleware
	} else {
		// DB key takes priority — if setup has run, the DB key is the real one.
		// Only fall back to the YAML key if the DB has nothing yet (fresh install
		// before setup wizard has been completed).
		validKeys := cfg.Auth.APIKeys
		if dbKey := db.GetAgentAPIKey(context.Background()); dbKey != "" {
			validKeys = []string{dbKey}
			logger.Info("auth: using agent API key from database")
		} else {
			logger.Info("auth: no DB key yet — using key(s) from server.yaml")
		}
		authMiddleware = auth.APIKeyMiddleware(validKeys)
	}

	protected := http.NewServeMux()
	SetTrustedProxies(cfg.Server.TrustedProxies) // M-13
	protected.HandleFunc("POST /api/v1/events", handleIngest(db, cfg.Server.MaxBatchSize, logger))
	protected.HandleFunc("POST /api/v1/agents/location", handleUpdateAgentLocation(db, logger))
	protected.HandleFunc("GET /api/v1/events", handleQueryEvents(db))
	protected.HandleFunc("GET /api/v1/metrics", handleMetrics())
	protected.HandleFunc("GET /api/v1/agents", handleListAgents(db))
	protected.HandleFunc("GET /api/v1/agents/{id}", handleGetAgent(db))

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
		} else {
			tlsCfg, err = auth.TLSConfig(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		}
		if err != nil {
			return nil, err
		}
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
		// TLS config already loaded — use empty strings so ListenAndServeTLS
		// uses the pre-loaded config.
		return s.http.ListenAndServeTLS("", "")
	}
	return s.http.ListenAndServe()
}

// Shutdown gracefully drains connections.
func (s *Server) Shutdown(ctx context.Context) error {
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
