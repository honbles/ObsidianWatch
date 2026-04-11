//go:build darwin

package service

// service.go — macOS launchd service management for ObsidianWatch agent.
// Config is embedded in the binary — no agent.yaml file needed on disk.

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

	"obsidianwatch/macos-agent/internal/config"
)

const (
	BinaryDst   = "/usr/local/bin/obsidianwatch-agent"
	ConfigDir   = "/etc/obsidianwatch"
	PlistPath   = "/Library/LaunchDaemons/com.obsidianwatch.agent.plist"
	QueueDir    = "/var/lib/obsidianwatch"
	ServiceName = "com.obsidianwatch.agent"
	LogDir      = "/var/log/obsidianwatch"
)

type InstallConfig struct {
	BinarySrc           string
	ManagementURL       string
	CAFile              string
	CACertPEM           string // backend CA — inline PEM
	ManagementCACertPEM string // management CA — inline PEM; falls back to CACertPEM if empty
	AgentID             string
	Hostname            string
}

func Install(cfg InstallConfig) error {
	// If already installed — unload daemon and replace binary cleanly.
	if _, err := os.Stat(BinaryDst); err == nil {
		fmt.Println("Existing installation detected — upgrading...")
		run("launchctl", "unload", PlistPath)
		os.Chmod(BinaryDst, 0755) // ensure writable
	}

	installKey, err := generateInstallKey()
	if err != nil {
		return fmt.Errorf("generate install key: %w", err)
	}

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

	for _, dir := range []string{ConfigDir, QueueDir, LogDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// Install the binary — config is embedded inside it, no yaml file needed.
	fmt.Printf("Installing binary to %s...\n", BinaryDst)
	if err := copyFile(cfg.BinarySrc, BinaryDst, 0755); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}

	// Persist the install key to a state file.
	if err := config.PersistInstallKey(installKey); err != nil {
		fmt.Printf("Warning: could not persist install key: %v\n", err)
	}

	fmt.Printf("Installing launchd plist to %s...\n", PlistPath)
	if err := writePlist(); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	fmt.Println("Loading service with launchctl...")
	exec.Command("launchctl", "unload", PlistPath).Run()
	if out, err := exec.Command("launchctl", "load", "-w", PlistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl load: %w\n%s", err, out)
	}

	fmt.Println("ObsidianWatch agent installed and started successfully.")
	fmt.Printf("Logs: %s/agent.log\n", LogDir)
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

	exec.Command("launchctl", "unload", "-w", PlistPath).Run()

	for _, path := range []string{PlistPath, BinaryDst, ConfigDir} {
		os.RemoveAll(path)
	}

	fmt.Println("ObsidianWatch agent uninstalled.")
	return nil
}

func writePlist() error {
	// No --config flag needed — config is embedded in the binary.
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s/agent.log</string>
    <key>StandardErrorPath</key>
    <string>%s/agent.log</string>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
    <key>ThrottleInterval</key>
    <integer>5</integer>
</dict>
</plist>`, ServiceName, BinaryDst, LogDir, LogDir)

	return os.WriteFile(PlistPath, []byte(plist), 0644)
}

func generateInstallKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func registerInstallKey(managementURL, caFile, caCertPEM, agentID, hostname, installKey string) error {
	payload, _ := json.Marshal(map[string]string{
		"agent_id":    agentID,
		"hostname":    hostname,
		"install_key": installKey,
		"os":          "macos",
	})
	client, err := buildHTTPClient(caFile, caCertPEM)
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

// buildHTTPClient builds an HTTP client. Prefers inline caCertPEM over a file path.
func buildHTTPClient(caFile, caCertPEM string) (*http.Client, error) {
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
		pool.AppendCertsFromPEM(caPEM)
		tlsCfg.RootCAs = pool
	} else {
		tlsCfg.InsecureSkipVerify = true
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   15 * time.Second,
	}, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// run executes a command silently, ignoring errors (used for cleanup steps
// like unloading a plist that may not exist yet).
func run(name string, args ...string) {
	exec.Command(name, args...).Run()
}
