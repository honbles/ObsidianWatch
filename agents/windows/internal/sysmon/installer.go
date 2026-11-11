//go:build windows

package sysmon

// installer.go — automatically detects and installs Sysmon if not present.
//
// Two modes:
//   1. Embedded binary (build with -tags embed_sysmon):
//      Place Sysmon64.exe in agent/internal/sysmon/embed/Sysmon64.exe
//      before building. The binary is compiled into the agent exe.
//
//   2. Download mode (default):
//      Downloads Sysmon.zip from Microsoft Sysinternals and installs silently.
//
// Sysmon is installed with a minimal config that captures:
//   - Process creation with command line (Event ID 1)
//   - Network connections (Event ID 3)
//   - File creation (Event ID 11)
//   - Registry events (Event IDs 12, 13)
//   - DNS queries (Event ID 22)

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	sysmonDownloadURL = "https://download.sysinternals.com/files/Sysmon.zip"
	sysmonInstallDir  = `C:\Windows\System32`
	sysmonConfigName  = "sysmon-config.xml"
)

// Sysmon config (W-03) — a reviewed baseline. Version it by bumping
// sysmonConfigVersion; a running Sysmon is re-configured when the embedded
// config's hash differs from the last one applied (see ensureConfigCurrent).
//
// Design notes:
//   - svchost.exe is NOT excluded from process-create/network: injected or
//     spoofed svchost is a favourite C2 carrier.
//   - Event IDs covered: 1,3,6,7,8,9,10,11,12/13/14,15,17/18,19/20/21,22,26.
//   - Registry/file watch lists cover IFEO, COM hijack, services, Winlogon,
//     LSA/security providers, Active Setup, Startup folders and scheduled tasks.
const sysmonConfigVersion = "2"

const sysmonConfig = `<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>

    <!-- 1 — Process Create: log everything except console-host / WER noise -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
        <Image condition="is">C:\Windows\System32\WerFault.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- 3 — Network Connect: only drop NetBIOS chatter and loopback -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <DestinationPort condition="is">137</DestinationPort>
        <DestinationPort condition="is">138</DestinationPort>
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
        <DestinationIp condition="is">::1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>

    <!-- 6 — Driver Load: unsigned or revoked drivers -->
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <Signed condition="is">false</Signed>
        <SignatureStatus condition="is not">Valid</SignatureStatus>
      </DriverLoad>
    </RuleGroup>

    <!-- 7 — Image/DLL Load: scripting engines, .NET/AMSI in odd hosts, user-writable paths -->
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <Image condition="contains">powershell</Image>
        <Image condition="contains">mshta</Image>
        <Image condition="contains">wscript</Image>
        <Image condition="contains">cscript</Image>
        <ImageLoaded condition="contains">\Temp\</ImageLoaded>
        <ImageLoaded condition="contains">\AppData\</ImageLoaded>
        <ImageLoaded condition="contains">\Users\Public\</ImageLoaded>
        <ImageLoaded condition="contains">\ProgramData\</ImageLoaded>
        <ImageLoaded condition="end with">amsi.dll</ImageLoaded>
        <ImageLoaded condition="end with">clrjit.dll</ImageLoaded>
        <ImageLoaded condition="end with">samlib.dll</ImageLoaded>
        <ImageLoaded condition="end with">vaultcli.dll</ImageLoaded>
        <ImageLoaded condition="end with">dbghelp.dll</ImageLoaded>
        <ImageLoaded condition="end with">dbgcore.dll</ImageLoaded>
      </ImageLoad>
    </RuleGroup>

    <!-- 8 — CreateRemoteThread into sensitive processes or from user paths -->
    <RuleGroup name="" groupRelation="or">
      <CreateRemoteThread onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
        <TargetImage condition="end with">winlogon.exe</TargetImage>
        <TargetImage condition="end with">explorer.exe</TargetImage>
        <TargetImage condition="end with">svchost.exe</TargetImage>
        <TargetImage condition="end with">services.exe</TargetImage>
        <TargetImage condition="end with">spoolsv.exe</TargetImage>
        <SourceImage condition="contains">\AppData\</SourceImage>
        <SourceImage condition="contains">\Temp\</SourceImage>
        <SourceImage condition="contains">\Users\Public\</SourceImage>
      </CreateRemoteThread>
    </RuleGroup>

    <!-- 9 — Raw disk access (credential/NTDS/SAM theft, wipers): log all -->
    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="exclude" />
    </RuleGroup>

    <!-- 10 — Process Access: LSASS plus injection-grade access to other processes -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
        <GrantedAccess condition="is">0x1F3FFF</GrantedAccess>
        <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
        <GrantedAccess condition="is">0x143A</GrantedAccess>
      </ProcessAccess>
    </RuleGroup>

    <!-- 11 — File Create: user-writable paths, executables/scripts, persistence folders -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\</TargetFilename>
        <TargetFilename condition="contains">\Users\Public\</TargetFilename>
        <TargetFilename condition="contains">\Start Menu\Programs\Startup\</TargetFilename>
        <TargetFilename condition="contains">\Windows\System32\Tasks\</TargetFilename>
        <TargetFilename condition="contains">\Windows\System32\drivers\</TargetFilename>
        <TargetFilename condition="contains">\Windows\System32\wbem\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.sys</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.psm1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.cmd</TargetFilename>
        <TargetFilename condition="end with">.vbs</TargetFilename>
        <TargetFilename condition="end with">.js</TargetFilename>
        <TargetFilename condition="end with">.hta</TargetFilename>
        <TargetFilename condition="end with">.lnk</TargetFilename>
        <TargetFilename condition="end with">.scr</TargetFilename>
        <TargetFilename condition="end with">.iso</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- 12/13/14 — Registry: persistence and defence-evasion keys -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">Policies\Explorer\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\Winlogon</TargetObject>
        <TargetObject condition="contains">AppInit_DLLs</TargetObject>
        <TargetObject condition="contains">Image File Execution Options</TargetObject>
        <TargetObject condition="contains">SilentProcessExit</TargetObject>
        <TargetObject condition="contains">\InprocServer32</TargetObject>
        <TargetObject condition="contains">\LocalServer32</TargetObject>
        <TargetObject condition="contains">\TreatAs</TargetObject>
        <TargetObject condition="contains">Classes\CLSID\</TargetObject>
        <TargetObject condition="contains">CurrentControlSet\Services\</TargetObject>
        <TargetObject condition="contains">Control\Session Manager</TargetObject>
        <TargetObject condition="contains">Control\Lsa</TargetObject>
        <TargetObject condition="contains">Control\SecurityProviders</TargetObject>
        <TargetObject condition="contains">Control\Print\Monitors</TargetObject>
        <TargetObject condition="contains">Active Setup\Installed Components</TargetObject>
        <TargetObject condition="contains">Windows\CurrentVersion\Policies\System</TargetObject>
        <TargetObject condition="contains">Windows Defender\Exclusions</TargetObject>
        <TargetObject condition="contains">Windows Defender\Real-Time Protection</TargetObject>
        <TargetObject condition="contains">Microsoft\Windows NT\CurrentVersion\Windows</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- 15 — FileCreateStreamHash: downloads (Mark-of-the-Web) and ADS -->
    <RuleGroup name="" groupRelation="or">
      <FileCreateStreamHash onmatch="include">
        <TargetFilename condition="contains">\Downloads\</TargetFilename>
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\</TargetFilename>
      </FileCreateStreamHash>
    </RuleGroup>

    <!-- 17/18 — Named pipes used by common C2 / lateral-movement tooling -->
    <RuleGroup name="" groupRelation="or">
      <PipeEvent onmatch="include">
        <PipeName condition="contains">msagent_</PipeName>
        <PipeName condition="contains">postex_</PipeName>
        <PipeName condition="contains">status_</PipeName>
        <PipeName condition="contains">MSSE-</PipeName>
        <PipeName condition="contains">psexesvc</PipeName>
        <PipeName condition="contains">paexec</PipeName>
        <PipeName condition="contains">remcom</PipeName>
        <PipeName condition="contains">csexec</PipeName>
        <PipeName condition="contains">isapi_http</PipeName>
        <PipeName condition="contains">isapi_dg</PipeName>
        <PipeName condition="contains">sdlrpc</PipeName>
        <PipeName condition="contains">mojo.</PipeName>
        <PipeName condition="contains">wkssvc</PipeName>
      </PipeEvent>
    </RuleGroup>

    <!-- 19/20/21 — WMI event filters / consumers / bindings: log all (rare, high value) -->
    <RuleGroup name="" groupRelation="or">
      <WmiEvent onmatch="exclude" />
    </RuleGroup>

    <!-- 22 — DNS Query -->
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.windowsupdate.com</QueryName>
        <QueryName condition="end with">.update.microsoft.com</QueryName>
        <QueryName condition="end with">.delivery.mp.microsoft.com</QueryName>
      </DnsQuery>
    </RuleGroup>

    <!-- 26 — File Delete Detected (no archiving): attacker cleanup of tools/scripts -->
    <RuleGroup name="" groupRelation="or">
      <FileDeleteDetected onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\</TargetFilename>
        <TargetFilename condition="contains">\Users\Public\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.evtx</TargetFilename>
      </FileDeleteDetected>
    </RuleGroup>

  </EventFiltering>
</Sysmon>`

// Status represents the current Sysmon installation state.
type Status int

const (
	StatusNotInstalled Status = iota
	StatusInstalled
	StatusRunning
)

// Check returns the current Sysmon status without modifying anything.
func Check() Status {
	m, err := mgr.Connect()
	if err != nil {
		return StatusNotInstalled
	}
	defer m.Disconnect()

	for _, name := range []string{"Sysmon64", "Sysmon", "SysmonDrv"} {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		defer s.Close()
		status, err := s.Query()
		if err != nil {
			return StatusInstalled
		}
		if status.State == 4 { // SERVICE_RUNNING
			return StatusRunning
		}
		return StatusInstalled
	}
	return StatusNotInstalled
}

// EnsureInstalled checks if Sysmon is installed and running.
// If not, it installs and starts it automatically.
// Returns true if Sysmon is running after this call.
func EnsureInstalled(logger *slog.Logger) bool {
	status := Check()

	switch status {
	case StatusRunning:
		logger.Info("sysmon: already installed and running")
		ensureConfigCurrent(logger)
		return true

	case StatusInstalled:
		logger.Info("sysmon: installed but not running — starting")
		if err := startService(logger); err != nil {
			logger.Warn("sysmon: failed to start service", "err", err)
			return false
		}
		logger.Info("sysmon: service started")
		return true

	case StatusNotInstalled:
		logger.Info("sysmon: not installed — installing automatically")
		if err := install(logger); err != nil {
			logger.Warn("sysmon: auto-install failed", "err", err)
			return false
		}
		logger.Info("sysmon: installed and running successfully ✓")
		return true
	}
	return false
}

// install downloads (or extracts embedded) Sysmon and installs it.
func install(logger *slog.Logger) error {
	// Get the Sysmon binary
	sysmonExe, tempDir, err := getSysmonBinary(logger)
	if tempDir != "" {
		defer os.RemoveAll(tempDir)
	}
	if err != nil {
		return fmt.Errorf("get binary: %w", err)
	}

	// Write the config file
	configPath := filepath.Join(os.TempDir(), sysmonConfigName)
	if err := os.WriteFile(configPath, []byte(sysmonConfig), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	defer os.Remove(configPath)

	// Install: Sysmon64.exe -accepteula -i <config>
	logger.Info("sysmon: running installer", "binary", sysmonExe)
	cmd := exec.Command(sysmonExe, "-accepteula", "-i", configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install failed: %w\noutput: %s", err, string(out))
	}
	logger.Info("sysmon: installation output", "output", strings.TrimSpace(string(out)))

	// Wait for service to appear
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		if Check() == StatusRunning {
			return nil
		}
	}
	// Try starting manually if not yet running
	return startService(logger)
}

// getSysmonBinary returns the path to Sysmon64.exe.
// Uses embedded binary if built with -tags embed_sysmon,
// otherwise downloads from Microsoft.
func getSysmonBinary(logger *slog.Logger) (exePath string, tempDir string, err error) {
	// Check if embedded binary is available
	if data := getEmbeddedSysmon(); data != nil {
		logger.Info("sysmon: using embedded binary")
		dir, err := os.MkdirTemp("", "obsidianwatch-sysmon-*")
		if err != nil {
			return "", "", err
		}
		exePath = filepath.Join(dir, "Sysmon64.exe")
		if err := os.WriteFile(exePath, data, 0755); err != nil {
			os.RemoveAll(dir)
			return "", "", err
		}
		return exePath, dir, nil
	}

	// Download from Microsoft
	logger.Info("sysmon: downloading from Microsoft Sysinternals", "url", sysmonDownloadURL)
	return downloadSysmon(logger)
}

// downloadSysmon downloads and extracts Sysmon64.exe from the Sysinternals zip.
func downloadSysmon(logger *slog.Logger) (exePath string, tempDir string, err error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(sysmonDownloadURL)
	if err != nil {
		return "", "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	const maxDownload = 64 << 20 // Sysmon/config downloads are a few MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err == nil && len(data) > maxDownload {
		err = fmt.Errorf("download exceeds %d bytes", maxDownload)
	}
	if err != nil {
		return "", "", fmt.Errorf("read body: %w", err)
	}
	logger.Info("sysmon: downloaded", "bytes", len(data))

	// Extract Sysmon64.exe from the zip
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", "", fmt.Errorf("open zip: %w", err)
	}

	dir, err := os.MkdirTemp("", "obsidianwatch-sysmon-*")
	if err != nil {
		return "", "", err
	}

	for _, f := range zr.File {
		if strings.EqualFold(f.Name, "Sysmon64.exe") {
			rc, err := f.Open()
			if err != nil {
				os.RemoveAll(dir)
				return "", "", fmt.Errorf("extract: %w", err)
			}
			exePath = filepath.Join(dir, "Sysmon64.exe")
			out, err := os.Create(exePath)
			if err != nil {
				rc.Close()
				os.RemoveAll(dir)
				return "", "", err
			}
			_, err = io.Copy(out, rc)
			out.Close()
			rc.Close()
			if err != nil {
				os.RemoveAll(dir)
				return "", "", fmt.Errorf("write exe: %w", err)
			}
			// W-02: refuse to run an executable that isn't validly signed by Microsoft.
			if verr := verifySysmonSignature(exePath); verr != nil {
				os.RemoveAll(dir)
				return "", "", fmt.Errorf("sysmon signature check failed: %w", verr)
			}
			logger.Info("sysmon: extracted Sysmon64.exe (Authenticode signature verified)")
			return exePath, dir, nil
		}
	}
	os.RemoveAll(dir)
	return "", "", fmt.Errorf("Sysmon64.exe not found in zip")
}

// startService starts the Sysmon service if it exists but isn't running.
func startService(logger *slog.Logger) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	for _, name := range []string{"Sysmon64", "Sysmon"} {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		defer s.Close()
		status, err := s.Query()
		if err != nil {
			continue
		}
		if status.State == 4 { // already running
			return nil
		}
		if err := s.Start(); err != nil {
			return fmt.Errorf("start %s: %w", name, err)
		}
		// Wait up to 5s for it to start
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			st, err := s.Query()
			if err == nil && st.State == 4 {
				return nil
			}
		}
		return fmt.Errorf("service did not reach running state")
	}
	return fmt.Errorf("service not found")
}

// isAdmin checks if the current process has administrator privileges.
func IsAdmin() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var isElevated uint32
	var returnLen uint32
	err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&isElevated)),
		uint32(unsafe.Sizeof(isElevated)),
		&returnLen,
	)
	return err == nil && isElevated != 0
}

// verifySysmonSignature checks the Authenticode signature of the downloaded
// binary (W-02): it must be Valid and signed by Microsoft. A zip from a
// poisoned mirror/proxy would otherwise run as SYSTEM.
func verifySysmonSignature(exePath string) error {
	// The path is passed through the environment: with -Command, trailing
	// arguments are NOT exposed as $args, so the earlier $args[0] version was
	// always null and every install was rejected.
	ps := `$p = $env:OW_SYSMON_PATH; ` +
		`if (-not $p) { Write-Output 'STATUS:NoPath'; exit 3 }; ` +
		`$s = Get-AuthenticodeSignature -LiteralPath $p; ` +
		`if ($s.Status -ne 'Valid') { Write-Output ('STATUS:' + $s.Status); exit 2 }; ` +
		`Write-Output ('SUBJECT:' + $s.SignerCertificate.Subject)`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.Env = append(os.Environ(), "OW_SYSMON_PATH="+exePath)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("signature not valid (%s)", text)
	}
	if !strings.Contains(text, "O=Microsoft Corporation") {
		return fmt.Errorf("unexpected signer: %s", text)
	}
	return nil
}

// ensureConfigCurrent re-applies the embedded Sysmon config when it changed
// since the last one we applied (versioned, managed config — W-02/W-03).
func ensureConfigCurrent(logger *slog.Logger) {
	sum := sha256.Sum256([]byte(sysmonConfigVersion + "\n" + sysmonConfig))
	want := hex.EncodeToString(sum[:])
	stateDir := filepath.Join(os.Getenv("ProgramData"), "ObsidianWatch")
	stateFile := filepath.Join(stateDir, "sysmon-config.sha256")
	if cur, err := os.ReadFile(stateFile); err == nil && strings.TrimSpace(string(cur)) == want {
		return
	}
	exe := ""
	for _, c := range []string{`C:\Windows\Sysmon64.exe`, `C:\Windows\Sysmon.exe`} {
		if _, err := os.Stat(c); err == nil {
			exe = c
			break
		}
	}
	if exe == "" {
		return
	}
	configPath := filepath.Join(os.TempDir(), sysmonConfigName)
	if err := os.WriteFile(configPath, []byte(sysmonConfig), 0600); err != nil {
		return
	}
	defer os.Remove(configPath)
	out, err := exec.Command(exe, "-accepteula", "-c", configPath).CombinedOutput()
	if err != nil {
		logger.Warn("sysmon: config update failed", "err", err, "output", strings.TrimSpace(string(out)))
		return
	}
	os.MkdirAll(stateDir, 0700)
	os.WriteFile(stateFile, []byte(want), 0600)
	logger.Info("sysmon: configuration updated", "version", sysmonConfigVersion)
}
