//go:build linux

package service

// service.go — Linux systemd service management for ObsidianWatch agent.

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"obsidianwatch/linux-agent/internal/config"
)

const (
	BinaryDst   = "/usr/local/bin/obsidianwatch-agent"
	ConfigDir   = "/etc/obsidianwatch"
	UnitFile    = "/etc/systemd/system/obsidianwatch-agent.service"
	QueueDir    = "/var/lib/obsidianwatch"
	ServiceName = "obsidianwatch-agent"
)

type InstallConfig struct {
	BinarySrc          string
	ManagementURL      string
	CAFile             string
	CACertPEM          string // backend CA — inline PEM
	ManagementCACertPEM string // management CA — inline PEM; falls back to CACertPEM if empty
	AgentID            string
	Hostname           string
}

func Install(cfg InstallConfig) error {
	// If already installed — stop service, remove tamper protection, then reinstall cleanly.
	// This makes re-running install after a new agent build fully automatic.
	if _, err := os.Stat(BinaryDst); err == nil {
		fmt.Println("Existing installation detected — upgrading...")
		removeTamper()
		run("systemctl", "stop", ServiceName)
		run("systemctl", "disable", ServiceName)
	}

	// Generate a cryptographically random install key — no manual entry needed.
	installKey, err := generateInstallKey()
	if err != nil {
		return fmt.Errorf("generate install key: %w", err)
	}

	// Register the key with the management server so it appears on the dashboard.
	if cfg.ManagementURL != "" {
		fmt.Println("Registering agent with management server...")
		// Use management CA if provided, fall back to backend CA.
		mgmtCA := cfg.ManagementCACertPEM
		if mgmtCA == "" {
			mgmtCA = cfg.CACertPEM
		}
		if err := registerInstallKey(cfg.ManagementURL, cfg.CAFile, mgmtCA, cfg.AgentID, cfg.Hostname, installKey); err != nil {
			fmt.Printf("Warning: could not register with management server: %v\n", err)
			fmt.Println("The key is saved locally and will sync when the server is reachable.")
		} else {
			fmt.Println("Agent registered on dashboard OK.")
		}
	}

	for _, dir := range []string{ConfigDir, QueueDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// Install the binary — config is embedded inside it, no yaml file needed.
	fmt.Printf("Installing binary to %s...\n", BinaryDst)
	if err := copyFile(cfg.BinarySrc, BinaryDst, 0755); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}

	// Persist the install key to a state file (config is embedded, not on disk).
	if err := config.PersistInstallKey(installKey); err != nil {
		fmt.Printf("Warning: could not persist install key: %v\n", err)
	}

	fmt.Printf("Writing systemd unit %s...\n", UnitFile)
	if err := writeUnit(); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}

	fmt.Println("Enabling and starting service...")
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", "--now", ServiceName},
	} {
		if out, err := run("systemctl", args...); err != nil {
			return fmt.Errorf("systemctl %v: %w\n%s", args, err, out)
		}
	}

	applyTamper()
	fmt.Println("ObsidianWatch agent installed and running.")
	fmt.Println("To verify: systemctl status obsidianwatch-agent")
	return nil
}

func Uninstall(managementURL, caFile, agentID string) error {
	// Read the persisted install key from the state file.
	installKey, err := config.ReadInstallKey()
	if err != nil || installKey == "" {
		return fmt.Errorf("could not read install key — was this agent installed with this tool?\n(expected at %s)", config.InstallKeyFile())
	}

	// ── Tamper protection: require admin to enter the key ────────────────────
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════╗")
	fmt.Println("  ║          ObsidianWatch Tamper Protection             ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("  To uninstall, enter the install key shown on the dashboard.")
	fmt.Println("  (Agents → select agent → shield icon)")
	fmt.Println()
	fmt.Print("  Enter install key: ")

	var inputKey string
	fmt.Scanln(&inputKey)
	inputKey = strings.TrimSpace(inputKey)

	if inputKey != installKey {
		fmt.Println()
		fmt.Println("  ✗ Incorrect key. Uninstall blocked.")
		return fmt.Errorf("tamper protection: incorrect install key")
	}
	fmt.Println("  ✓ Key accepted. Proceeding with uninstall...")
	fmt.Println()

	removeTamper()
	run("systemctl", "stop", ServiceName)
	run("systemctl", "disable", ServiceName)
	os.Remove(UnitFile)
	run("systemctl", "daemon-reload")
	run("systemctl", "reset-failed")
	os.Remove(BinaryDst)
	os.RemoveAll(ConfigDir)
	os.RemoveAll(QueueDir)

	fmt.Println("ObsidianWatch agent uninstalled.")
	return nil
}

func writeUnit() error {
	unit := `[Unit]
Description=ObsidianWatch Security Agent
Documentation=https://obsidianwatch.io
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/obsidianwatch-agent
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=obsidianwatch-agent
User=root
Group=root
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/obsidianwatch /etc/obsidianwatch /etc/shadow /etc/passwd /etc/group
PrivateTmp=true
ProtectHome=read-only
RestrictSUIDSGID=true
LockPersonality=true
LimitNOFILE=65536
MemoryMax=256M
CPUQuota=25%

[Install]
WantedBy=multi-user.target
`
	return os.WriteFile(UnitFile, []byte(unit), 0644)
}

func applyTamper() {
	run("chattr", "+i", BinaryDst)
	run("chattr", "+i", UnitFile)
	run("chattr", "+i", config.InstallKeyFile())
	fmt.Println("Tamper protection applied (chattr +i).")
}

func removeTamper() {
	run("chattr", "-i", BinaryDst)
	run("chattr", "-i", UnitFile)
	run("chattr", "-i", config.InstallKeyFile())
}

// generateInstallKey returns a 32-character cryptographically random hex string.
func generateInstallKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// registerInstallKey posts the agent's auto-generated key to the management server.
func registerInstallKey(managementURL, caFile, caCertPEM, agentID, hostname, installKey string) error {
	payload, _ := json.Marshal(map[string]string{
		"agent_id":    agentID,
		"hostname":    hostname,
		"install_key": installKey,
		"os":          "linux",
	})
	client, err := buildClient(caFile, caCertPEM)
	if err != nil {
		return err
	}
	resp, err := client.Post(managementURL+"/api/v1/agent/register-key", "application/json",
		strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("management server unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// buildClient builds an HTTP client. Prefers inline caCertPEM over a file path.
func buildClient(caFile, caCertPEM string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	var caPEM []byte
	switch {
	case caCertPEM != "":
		caPEM = []byte(caCertPEM)
	case caFile != "":
		var err error
		caPEM, err = os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
	}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA cert")
		}
		tlsCfg.RootCAs = pool
	} else {
		tlsCfg.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   15 * time.Second,
	}, nil
}

func run(cmd string, args ...string) (string, error) {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	return string(out), err
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func init() { _ = filepath.Join }
