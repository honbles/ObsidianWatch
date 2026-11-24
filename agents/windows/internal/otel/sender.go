package otel

// sender.go - delivers batches to POST /api/v1/app/batch over the agent's existing
// outbound HTTPS connection settings (same CA, client certificate and API key as the
// event forwarder). Outbound only; nothing here listens.

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
	"strconv"
	"sync/atomic"
	"time"

	"obsidianwatch/agent/internal/identity"
)

// SenderOptions mirrors the forwarder's connection settings.
type SenderOptions struct {
	BackendURL string
	APIKey     string
	CACertPEM  string
	CAFile     string
	CertFile   string
	KeyFile    string
	Version    string
}

type Sender struct {
	opt    SenderOptions
	client *http.Client
	q      chan *Batch
	log    *slog.Logger
	onFail func(*Batch) // statistics are handed back for the next flush
	Sent   atomic.Int64
	Failed atomic.Int64
	Drops  atomic.Int64
}

func NewSender(opt SenderOptions, onFail func(*Batch), logger *slog.Logger) (*Sender, error) {
	c, err := buildClient(opt)
	if err != nil {
		return nil, err
	}
	return &Sender{opt: opt, client: c, q: make(chan *Batch, 100), log: logger, onFail: onFail}, nil
}

func buildClient(o SenderOptions) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if o.CertFile != "" && o.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	var caPEM []byte
	switch {
	case o.CACertPEM != "":
		caPEM = []byte(o.CACertPEM)
	case o.CAFile != "":
		b, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		caPEM = b
	}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA cert: invalid PEM")
		}
		tlsCfg.RootCAs = pool
	}
	identity.ApplyActive(tlsCfg) // the agent's enrolled certificate
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true},
		Timeout:   30 * time.Second,
	}, nil
}

// Send queues a batch; when the queue is full the oldest batch is dropped and counted
// (backpressure drops oldest first, spec section 12).
func (s *Sender) Send(b *Batch) {
	for {
		select {
		case s.q <- b:
			return
		default:
			select {
			case old := <-s.q:
				s.Drops.Add(1)
				if s.onFail != nil {
					s.onFail(old)
				}
			default:
			}
		}
	}
}

// Run delivers queued batches until ctx ends, then drains what is left quickly.
func (s *Sender) Run(ctx context.Context) {
	for {
		select {
		case b := <-s.q:
			s.deliver(ctx, b)
		case <-ctx.Done():
			for {
				select {
				case b := <-s.q:
					dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					s.post(dctx, b)
					cancel()
				default:
					return
				}
			}
		}
	}
}

func (s *Sender) deliver(ctx context.Context, b *Batch) {
	backoff := time.Second
	// ctx only aborts the wait between attempts; a post already picked up is always
	// attempted, so the final flush at shutdown is not lost to the cancelled context.
	pctx := context.WithoutCancel(ctx)
	for attempt := 0; attempt < 3; attempt++ {
		code, wait, err := s.post(pctx, b)
		if err == nil {
			s.Sent.Add(1)
			return
		}
		if wait == 0 { // non-retryable: the backend said no
			s.Failed.Add(1)
			s.log.Warn("app batch rejected, dropping", "status", code, "err", err)
			return
		}
		if attempt == 2 { // out of attempts: no point sleeping before handing the batch back
			break
		}
		if wait < backoff {
			wait = backoff
		}
		select {
		case <-time.After(wait):
			backoff *= 3
		case <-ctx.Done():
			s.requeue(b)
			return
		}
	}
	s.requeue(b)
}

func (s *Sender) requeue(b *Batch) {
	s.Failed.Add(1)
	if s.onFail != nil {
		s.onFail(b)
	}
}

// post sends one batch. retry is true for failures worth retrying.
func (s *Sender) post(ctx context.Context, b *Batch) (code int, retry time.Duration, err error) {
	body, err := json.Marshal(b)
	if err != nil {
		return 0, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.opt.BackendURL+"/api/v1/app/batch", bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "obsidianwatch-agent/"+s.opt.Version)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, time.Second, err // network error: retry
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return resp.StatusCode, 0, nil
	}
	if ra, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && ra > 0 && ra < 120 {
		retry = time.Duration(ra) * time.Second
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		if retry == 0 {
			retry = time.Second
		}
		return resp.StatusCode, retry, fmt.Errorf("retryable HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, 0, fmt.Errorf("non-retryable HTTP %d", resp.StatusCode)
}
