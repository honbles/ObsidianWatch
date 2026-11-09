//go:build darwin

package service

// service.go — macOS launchd service management for ObsidianWatch agent.
// Config is embedded in the binary — no agent.yaml file needed on disk.

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
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
	APIKey              string // fleet API key (X-API-Key) required by register-key / verify-install-key
	AgentID             string
	Hostname            string
}

func Install(cfg InstallConfig) error {
	// If already installed — unload daemon and replace binary cleanly.
	if _, err := os.Stat(BinaryDst); err == nil {
		fmt.Println("Existing installation detected — upgrading...")
		run("launchctl", "unload", PlistPath)
		removeTamper()            // F-01: must clear uchg before we can overwrite these files
		os.Chmod(BinaryDst, 0700) // ensure writable
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
		if err := registerInstallKey(cfg.ManagementURL, cfg.CAFile, mgmtCA, cfg.APIKey, cfg.AgentID, cfg.Hostname, installKey); err != nil {
			fmt.Printf("Warning: could not register with management server: %v\n", err)
			fmt.Println("The key is saved locally and will sync when the server is reachable.")
		} else {
			fmt.Println("Agent registered on dashboard OK.")
		}
	}

	for _, dir := range []string{ConfigDir, QueueDir, LogDir} {
		// The queue holds unsent telemetry and the config dir holds the
		// install key: root-only.
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	// Install the binary — config is embedded inside it, no yaml file needed.
	fmt.Printf("Installing binary to %s...\n", BinaryDst)
	if err := copyFile(cfg.BinarySrc, BinaryDst, 0700); err != nil {
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

	// F-01: the dashboard's tamper toggle was previously cosmetic — it had
	// no agent-side enforcement, so "off" vs "on" made no real difference
	// and nothing actually required the install key to remove the agent.
	// This applies real OS-level immutability (chflags uchg), matching what
	// the Linux (chattr +i) and Windows (service DACL) agents already do:
	// the files genuinely cannot be deleted or modified — including by a
	// root user running `rm` directly, bypassing this CLI entirely — until
	// removeTamper() clears the flag, which only this Uninstall() does,
	// and only after the install key is verified.
	applyTamper()

	fmt.Println("ObsidianWatch agent installed and started successfully.")
	fmt.Printf("Logs: %s/agent.log\n", LogDir)
	return nil
}

func applyTamper() {
	run("chflags", "uchg", BinaryDst)
	run("chflags", "uchg", PlistPath)
	run("chflags", "uchg", config.InstallKeyFile())
	fmt.Println("Tamper protection applied (chflags uchg).")
}

func removeTamper() {
	run("chflags", "nouchg", BinaryDst)
	run("chflags", "nouchg", PlistPath)
	run("chflags", "nouchg", config.InstallKeyFile())
}

func Uninstall(managementURL, caFile, caCertPEM, apiKey, agentID string) error {
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

	// F-02: the management server is the authority — it verifies the key and
	// rotates it (single-use), so "Regenerate key" on the dashboard actually
	// works. The local copy is consulted only when the server cannot be
	// reached at all; a server rejection is final.
	accepted, reachable := verifyInstallKey(managementURL, caFile, caCertPEM, apiKey, inputKey)
	if reachable {
		if !accepted {
			fmt.Println()
			fmt.Println("  ✗ Incorrect key. Uninstall blocked.")
			return fmt.Errorf("tamper protection: incorrect install key")
		}
	} else if subtle.ConstantTimeCompare([]byte(inputKey), []byte(installKey)) != 1 {
		fmt.Println()
		fmt.Println("  ✗ Incorrect key (management server unreachable; checked against local copy). Uninstall blocked.")
		return fmt.Errorf("tamper protection: incorrect install key")
	}
	fmt.Println("  ✓ Key accepted. Proceeding with uninstall...")
	fmt.Println()

	removeTamper() // F-01: clear uchg — only reached after key verification above
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

func registerInstallKey(managementURL, caFile, caCertPEM, apiKey, agentID, hostname, installKey string) error {
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
	req, err := http.NewRequest(http.MethodPost, managementURL+"/api/v1/agent/register-key",
		strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := client.Do(req)
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
// A-05: hard-fails via config.BuildTLSConfig instead of silently accepting
// any certificate when no CA is configured.
func buildHTTPClient(caFile, caCertPEM string) (*http.Client, error) {
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

// verifyInstallKey (F-02) asks the management server to verify the key via
// POST body + X-API-Key. reachable=false means the server could not be
// contacted at all (as opposed to contacted-and-rejected).
func verifyInstallKey(managementURL, caFile, caCertPEM, apiKey, key string) (accepted, reachable bool) {
	if managementURL == "" {
		return false, false
	}
	client, err := buildHTTPClient(caFile, caCertPEM)
	if err != nil {
		return false, false
	}
	payload, _ := json.Marshal(map[string]string{"key": key})
	req, err := http.NewRequest(http.MethodPost, managementURL+"/api/v1/verify-install-key",
		strings.NewReader(string(payload)))
	if err != nil {
		return false, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, true
}
