//go:build darwin

package collector

// location.go — macOS location collector.
//
// We use IP geolocation exclusively, via ipinfo.io over HTTPS.
//
// F-15: a plain-HTTP fallback to ip-api.com previously existed here. It has
// been removed: ip-api.com's free tier has no HTTPS option, and falling back
// to it leaked the host's public IP (and therefore its approximate location)
// in cleartext to any on-path observer. If ipinfo.io is unavailable we now
// simply report an error instead of silently downgrading to an insecure
// transport. A future improvement could derive location server-side from
// the ingest connection's source IP instead of having the agent call out to
// a third-party geolocation service at all.
//
// Posts location directly to the backend /api/v1/agents/location endpoint.
// Runs every 30 minutes — location data changes rarely.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"obsidianwatch/macos-agent/internal/config"
	"obsidianwatch/macos-agent/pkg/schema"
)

type LocationCollector struct {
	interval         time.Duration
	agentID          string
	hostname         string
	backendURL       string
	apiKey           string
	caFile           string
	caCertPEM        string
	allowInsecureTLS bool
	out              chan<- schema.Event
	logger           *slog.Logger
}

func NewLocationCollector(interval time.Duration, agentID, hostname, backendURL, apiKey, caFile, caCertPEM string, allowInsecureTLS bool, out chan<- schema.Event, logger *slog.Logger) *LocationCollector {
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	return &LocationCollector{
		interval:         interval,
		agentID:          agentID,
		hostname:         hostname,
		backendURL:       backendURL,
		apiKey:           apiKey,
		caFile:           caFile,
		caCertPEM:        caCertPEM,
		allowInsecureTLS: allowInsecureTLS,
		out:              out,
		logger:           logger,
	}
}

func (c *LocationCollector) Run(ctx context.Context) error {
	c.logger.Info("location: collector started", "interval", c.interval)
	// Run immediately on start then on interval
	c.collect(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

type locationResult struct {
	Lat      float64
	Lng      float64
	Accuracy float64
	Source   string
	City     string
	Country  string
}

func (c *LocationCollector) collect(ctx context.Context) {
	loc, err := getIPGeolocation(ctx)
	if err != nil {
		c.logger.Warn("location: IP geolocation failed", "err", err)
		return
	}

	c.logger.Info("location: acquired",
		"lat", fmt.Sprintf("%.4f", loc.Lat),
		"lng", fmt.Sprintf("%.4f", loc.Lng),
		"accuracy_m", loc.Accuracy,
		"source", loc.Source,
		"city", loc.City,
	)

	if c.backendURL != "" {
		go c.postLocation(loc)
	}
}

func (c *LocationCollector) postLocation(loc locationResult) {
	body, _ := json.Marshal(map[string]interface{}{
		"agent_id": c.agentID,
		"hostname": c.hostname,
		"lat":      loc.Lat,
		"lng":      loc.Lng,
		"accuracy": loc.Accuracy,
		"source":   loc.Source,
		"city":     loc.City,
		"country":  loc.Country,
	})

	client := c.buildHTTPClient()
	backend := strings.TrimRight(c.backendURL, "/")
	req, err := http.NewRequest("POST", backend+"/api/v1/agents/location", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	resp, err := client.Do(req)
	if err != nil {
		c.logger.Warn("location: post failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body2, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.logger.Warn("location: backend returned error", "status", resp.StatusCode, "body", string(body2))
		return
	}
	c.logger.Info("location: posted to backend", "status", resp.StatusCode)
}

func (c *LocationCollector) buildHTTPClient() *http.Client {
	var pemData []byte
	switch {
	case c.caCertPEM != "":
		pemData = []byte(c.caCertPEM)
	case c.caFile != "":
		pemData, _ = os.ReadFile(c.caFile)
	}
	tlsCfg, err := config.BuildTLSConfig(pemData, c.allowInsecureTLS)
	if err != nil {
		c.logger.Error("location: TLS config error, requests will fail closed", "err", err)
		tlsCfg = &tls.Config{}
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// getIPGeolocation resolves an approximate location via ipinfo.io (HTTPS).
//
// F-15: this previously fell back to a plain-HTTP call to ip-api.com when
// ipinfo.io failed, which leaked the host's public IP in cleartext. That
// fallback has been removed; a failure here is now surfaced as an error
// instead of being masked by an insecure fallback.
func getIPGeolocation(ctx context.Context) (locationResult, error) {
	client := &http.Client{Timeout: 8 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	if err != nil {
		return locationResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return locationResult{}, fmt.Errorf("ipinfo.io request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		City    string `json:"city"`
		Country string `json:"country"`
		Loc     string `json:"loc"` // "lat,lng"
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return locationResult{}, fmt.Errorf("ipinfo.io: invalid response: %w", err)
	}
	if r.Loc == "" {
		return locationResult{}, fmt.Errorf("ipinfo.io: no location in response")
	}
	parts := strings.SplitN(r.Loc, ",", 2)
	if len(parts) != 2 {
		return locationResult{}, fmt.Errorf("ipinfo.io: malformed loc field %q", r.Loc)
	}
	var lat, lng float64
	fmt.Sscanf(parts[0], "%f", &lat)
	fmt.Sscanf(parts[1], "%f", &lng)
	if lat == 0 && lng == 0 {
		return locationResult{}, fmt.Errorf("ipinfo.io: zero coordinates")
	}
	return locationResult{
		Lat: lat, Lng: lng,
		Accuracy: 5000,
		Source:   "ip",
		City:     r.City,
		Country:  r.Country,
	}, nil
}
