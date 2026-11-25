//go:build linux

package service

// service.go - Linux systemd service management for ObsidianWatch agent.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"obsidianwatch/linux-agent/internal/response"
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
	BinarySrc           string
	ManagementURL       string // unused by the agent since enrollment; kept for older configs
	CAFile              string
	CACertPEM           string // backend CA - inline PEM
	ManagementCACertPEM string // management CA - inline PEM; falls back to CACertPEM if empty
	AgentID             string
	Hostname            string
	// Enroll gets the agent its certificate and registers the install key
	// through the backend. Failure is not fatal: the service finishes both
	// when it starts.
	Enroll func(installKey string) error
}

func Install(cfg InstallConfig) error {
	// If already installed - stop service, remove tamper protection, then reinstall cleanly.
	// This makes re-running install after a new agent build fully automatic.
	if _, err := os.Stat(BinaryDst); err == nil {
		fmt.Println("Existing installation detected - upgrading...")
		removeTamper()
		run("systemctl", "stop", ServiceName)
		run("systemctl", "disable", ServiceName)
	}

	// Generate a cryptographically random install key - no manual entry needed.
	installKey, err := generateInstallKey()
	if err != nil {
		return fmt.Errorf("generate install key: %w", err)
	}

	if cfg.Enroll != nil {
		fmt.Println("Enrolling the agent (getting its certificate) and registering it...")
		if err := cfg.Enroll(installKey); err != nil {
			fmt.Printf("Warning: %v\n", err)
			fmt.Println("The service will enroll and register as soon as it can reach the server.")
		} else {
			fmt.Println("Agent enrolled and registered on the dashboard.")
		}
	}

	for _, dir := range []string{ConfigDir, QueueDir} {
		// The queue holds unsent telemetry and the config dir holds the
		// install key: root-only.
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// Install the binary - config is embedded inside it, no yaml file needed.
	fmt.Printf("Installing binary to %s...\n", BinaryDst)
	if err := copyFile(cfg.BinarySrc, BinaryDst, 0700); err != nil {
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

	// One-click host isolation needs nftables (or iptables). Install it now, while we
	// are running outside the service sandbox, so isolation works the first time it is used.
	if err := response.EnsureFirewallTool(context.Background()); err != nil {
		fmt.Printf("Warning: %v\nHost isolation will not work until a firewall tool is installed.\n", err)
	} else {
		fmt.Println("Firewall tool for host isolation: OK")
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

// Uninstall removes the agent after the install key is verified. backendURL
// and caCertPEM reach the backend, which checks the agent certificate and
// passes the verification to the management server.
func Uninstall(backendURL, caFile, caCertPEM, agentID string) error {
	// Read the persisted install key from the state file.
	installKey, err := config.ReadInstallKey()
	if err != nil || installKey == "" {
		return fmt.Errorf("could not read install key - was this agent installed with this tool?\n(expected at %s)", config.InstallKeyFile())
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

	// F-02: the server is the authority - it verifies the key and
	// rotates it (single-use), so "Regenerate key" on the dashboard actually
	// works. The local copy is consulted only when the server cannot be
	// reached at all; a server rejection is final.
	accepted, reachable := verifyInstallKey(backendURL, caFile, caCertPEM, inputKey)
	if reachable {
		if !accepted {
			fmt.Println()
			fmt.Println("  ✗ Incorrect key. Uninstall blocked.")
			return fmt.Errorf("tamper protection: incorrect install key")
		}
	} else if subtle.ConstantTimeCompare([]byte(inputKey), []byte(installKey)) != 1 {
		fmt.Println()
		fmt.Println("  ✗ Incorrect key (server could not verify; checked against local copy). Uninstall blocked.")
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
	return os.WriteFile(UnitFile, []byte(unitText()), 0644)
}

func unitText() string {
	return `[Unit]
Description=ObsidianWatch Security Agent
Documentation=https://obsidianwatch.io
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/obsidianwatch-agent
Restart=always
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=obsidianwatch-agent
User=root
Group=root
NoNewPrivileges=true
# No ProtectSystem/ProtectHome/PrivateTmp: the agent must see the host's real
# /tmp and home directories (file monitoring, quarantine, delete) and write
# system files for response actions (disable account) and the live-response
# shell. A read-only or private view breaks all of these.
RestrictSUIDSGID=true
LockPersonality=true
LimitNOFILE=65536
MemoryMax=256M
CPUQuota=25%

[Install]
WantedBy=multi-user.target
`
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

// verifyInstallKey (F-02) asks the server to verify the key. The request
// goes to the backend with the agent certificate. reachable=false means the
// server could not give an answer about this agent (unreachable, or the
// identity is gone), so the local copy decides.
func verifyInstallKey(backendURL, caFile, caCertPEM, key string) (accepted, reachable bool) {
	if backendURL == "" {
		return false, false
	}
	client, err := buildClient(caFile, caCertPEM)
	if err != nil {
		return false, false
	}
	payload, _ := json.Marshal(map[string]string{"key": key})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(backendURL, "/")+"/api/v1/verify-install-key",
		strings.NewReader(string(payload)))
	if err != nil {
		return false, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 { // no valid agent certificate: the server cannot judge
		return false, false
	}
	return resp.StatusCode == 200, true
}

// generateInstallKey returns a 32-character cryptographically random hex string.
func generateInstallKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RegisterInstallKey posts the agent's install key through the backend,
// authenticated by the agent certificate.
func RegisterInstallKey(backendURL, caFile, caCertPEM, agentID, hostname, installKey string) error {
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
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(backendURL, "/")+"/api/v1/agent/register-key",
		strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// buildClient builds an HTTP client. Prefers inline caCertPEM over a file path.
// L-05: no allowInsecure plumbing reaches this call site (it's only used
// during install/registration, where a CA should always be available), so
// this hard-fails via config.BuildTLSConfig rather than silently accepting
// any certificate the way it used to.
func buildClient(caFile, caCertPEM string) (*http.Client, error) {
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
	tlsCfg, err := config.BuildTLSConfig(caPEM, false)
	if err != nil {
		return nil, err
	}
	tlsCfg.MinVersion = tls.VersionTLS12
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
