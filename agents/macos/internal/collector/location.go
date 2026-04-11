//go:build darwin

package collector

// location.go — macOS location collector.
//
// Linux has no kernel location API, so we use IP geolocation exclusively.
// Sources tried in order:
//  1. ipinfo.io  — HTTPS, reliable, good city-level precision
//  2. ip-api.com — HTTP fallback
//
// Posts location directly to the backend /api/v1/agents/location endpoint.
// Runs every 30 minutes — location data changes rarely.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

type LocationCollector struct {
	interval   time.Duration
	agentID    string
	hostname   string
	backendURL string
	apiKey     string
	caFile     string
	caCertPEM  string
	out        chan<- schema.Event
	logger     *slog.Logger
}

func NewLocationCollector(interval time.Duration, agentID, hostname, backendURL, apiKey, caFile, caCertPEM string, out chan<- schema.Event, logger *slog.Logger) *LocationCollector {
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	return &LocationCollector{
		interval:   interval,
		agentID:    agentID,
		hostname:   hostname,
		backendURL: backendURL,
		apiKey:     apiKey,
		caFile:     caFile,
		caCertPEM:  caCertPEM,
		out:        out,
		logger:     logger,
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
		body2, _ := io.ReadAll(resp.Body)
		c.logger.Warn("location: backend returned error", "status", resp.StatusCode, "body", string(body2))
		return
	}
	c.logger.Info("location: posted to backend", "status", resp.StatusCode)
}

func (c *LocationCollector) buildHTTPClient() *http.Client {
	tlsCfg := &tls.Config{}
	var pemData []byte
	switch {
	case c.caCertPEM != "":
		pemData = []byte(c.caCertPEM)
	case c.caFile != "":
		pemData, _ = os.ReadFile(c.caFile)
	}
	if len(pemData) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pemData)
		tlsCfg.RootCAs = pool
	} else {
		tlsCfg.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// getIPGeolocation tries ipinfo.io then ip-api.com as fallback.
func getIPGeolocation(ctx context.Context) (locationResult, error) {
	client := &http.Client{Timeout: 8 * time.Second}

	// Try ipinfo.io first
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	if err == nil {
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			var r struct {
				City    string `json:"city"`
				Country string `json:"country"`
				Loc     string `json:"loc"` // "lat,lng"
			}
			if json.Unmarshal(body, &r) == nil && r.Loc != "" {
				parts := strings.SplitN(r.Loc, ",", 2)
				if len(parts) == 2 {
					var lat, lng float64
					fmt.Sscanf(parts[0], "%f", &lat)
					fmt.Sscanf(parts[1], "%f", &lng)
					if lat != 0 || lng != 0 {
						return locationResult{
							Lat: lat, Lng: lng,
							Accuracy: 5000,
							Source:   "ip",
							City:     r.City,
							Country:  r.Country,
						}, nil
					}
				}
			}
		}
	}

	// Fallback: ip-api.com
	req2, err := http.NewRequestWithContext(ctx, "GET",
		"http://ip-api.com/json/?fields=lat,lon,city,country,status", nil)
	if err != nil {
		return locationResult{}, err
	}
	resp2, err := client.Do(req2)
	if err != nil {
		return locationResult{}, err
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	var r2 struct {
		Status  string  `json:"status"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
		City    string  `json:"city"`
		Country string  `json:"country"`
	}
	if err := json.Unmarshal(body2, &r2); err != nil || r2.Status != "success" {
		return locationResult{}, fmt.Errorf("ip-api: %s", r2.Status)
	}
	return locationResult{
		Lat: r2.Lat, Lng: r2.Lon,
		Accuracy: 5000,
		Source:   "ip",
		City:     r2.City,
		Country:  r2.Country,
	}, nil
}
