package forwarder

// http.go — batched HTTP/2 forwarder with mTLS and API-key fallback.
// Events are read from the local Queue and POSTed to the backend ingest API.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

// HTTPForwarder reads from the Queue and delivers batches to the backend.
type HTTPForwarder struct {
	cfg      ForwarderConfig
	queue    *Queue
	client   *http.Client
	retry    RetryPolicy
	logger   *slog.Logger
	agentID  string
	hostname string
	ver      string
}

// ForwarderConfig holds transport configuration.
type ForwarderConfig struct {
	InstallKey    string
	BackendURL    string
	BatchSize     int
	FlushInterval time.Duration
	// mTLS
	CertFile string
	KeyFile  string
	CAFile      string
	CACertPEM  string
	// API key (fallback when mTLS not configured)
	APIKey string
}

// NewHTTPForwarder creates the forwarder and builds the TLS-aware HTTP client.
func NewHTTPForwarder(cfg ForwarderConfig, queue *Queue, agentID, hostname, ver string, logger *slog.Logger) (*HTTPForwarder, error) {
	client, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("forwarder: build client: %w", err)
	}

	return &HTTPForwarder{
		cfg:      cfg,
		queue:    queue,
		client:   client,
		retry:    DefaultRetryPolicy(),
		logger:   logger,
		agentID:  agentID,
		hostname: hostname,
		ver:      ver,
	}, nil
}

// Run starts the flush loop until ctx is cancelled.
func (f *HTTPForwarder) Run(ctx context.Context) error {
	ticker := time.NewTicker(f.cfg.FlushInterval)
	defer ticker.Stop()

	f.logger.Info("forwarder: started", "url", f.cfg.BackendURL)

	for {
		select {
		case <-ctx.Done():
			// Drain remaining events before shutting down.
			f.flush(context.Background())
			return nil
		case <-ticker.C:
			f.flush(ctx)
		}
	}
}


// SendFinal (D-12) transmits one last event synchronously as the agent shuts
// down — typically "agent.tamper" (stop requested / signal received) — so the
// server sees a stop/uninstall attempt before the agent dies. It bypasses the
// queue ordering, waits at most 5 seconds, and falls back to the local queue
// if the backend is unreachable.
func (f *HTTPForwarder) SendFinal(ev schema.Event) {
	ev.AgentID = f.agentID
	ev.Host = f.hostname
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	batch := schema.Batch{
		AgentID:    f.agentID,
		Hostname:   f.hostname,
		AgentVer:   f.ver,
		InstallKey: f.cfg.InstallKey,
		SentAt:     time.Now().UTC(),
		Events:     []schema.Event{ev},
	}
	if err := f.send(ctx, batch); err != nil {
		f.logger.Warn("forwarder: final event send failed, queued locally", "err", err)
		f.Enqueue([]schema.Event{ev})
	}
}

// Enqueue pushes events into the local queue (non-blocking path from collectors).
func (f *HTTPForwarder) Enqueue(events []schema.Event) {
	if err := f.queue.Push(events); err != nil {
		f.logger.Error("forwarder: enqueue failed", "err", err)
	}
}

// flush pops one batch from the queue and sends it.
func (f *HTTPForwarder) flush(ctx context.Context) {
	events, err := f.queue.Pop(f.cfg.BatchSize)
	if err != nil {
		f.logger.Error("forwarder: queue pop failed", "err", err)
		return
	}
	if len(events) == 0 {
		return
	}

	batch := schema.Batch{
		AgentID:    f.agentID,
		Hostname:   f.hostname,
		AgentVer:   f.ver,
		InstallKey: f.cfg.InstallKey,
		SentAt:     time.Now().UTC(),
		Events:     events,
	}

	err = f.retry.Do(ctx, func() error {
		return f.send(ctx, batch)
	})
	if err != nil {
		f.logger.Error("forwarder: send failed after retries",
			"events", len(events), "err", err)
		// Re-queue so events are not lost.
		if pushErr := f.queue.Push(events); pushErr != nil {
			f.logger.Error("forwarder: re-queue failed", "err", pushErr)
		}
	} else {
		f.logger.Debug("forwarder: sent batch", "count", len(events))
	}
}

// send serialises the batch and POSTs it to the backend.
func (f *HTTPForwarder) send(ctx context.Context, batch schema.Batch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.cfg.BackendURL+"/api/v1/events", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "obsidianwatch-agent/"+f.ver)
	if f.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", f.cfg.APIKey)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated ||
		resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if IsRetryable(resp.StatusCode) {
		return fmt.Errorf("retryable HTTP %d", resp.StatusCode)
	}

	return fmt.Errorf("non-retryable HTTP %d", resp.StatusCode)
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

func buildHTTPClient(cfg ForwarderConfig) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load client certificate for mTLS.
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// Load CA cert — prefer inline PEM (embedded binary), fall back to file path.
	var caPEM []byte
	switch {
	case cfg.CACertPEM != "":
		caPEM = []byte(cfg.CACertPEM)
	case cfg.CAFile != "":
		var err error
		caPEM, err = os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
	}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA cert: invalid PEM")
		}
		tlsCfg.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		// HTTP/2 is automatically negotiated via ALPN when TLS is present.
		ForceAttemptHTTP2: true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}
