# ObsidianWatch — Search & Detection Reference

This document covers the Search system (100 saved queries) and the Threat Detection Library (35+ automated signatures) built into ObsidianWatch Management Platform v0.3.0.

---

## Search

### How it works

The Search page combines a **saved query library** with a **query builder**. You can:
1. Click any saved query to load its parameters into the builder
2. Add additional filters on top
3. Run the query and see results inline
4. Jump to the Events page for full drill-down

Queries are executed against the live TimescaleDB database — all filters are server-side, not in-browser. Results return up to 200 events by default.

### Supported filter fields

| Field | Parameter | Description |
|---|---|---|
| Event Type | `event_type` | process, network, logon, registry, file, dns, sysmon, raw |
| Process Name | `process_name` | Partial match on process executable name |
| Command Line | `command_line` | Partial match on full command line |
| Image Path | `image_path` | Partial match on full executable path |
| User | `user_name` | Partial match on username |
| Src IP | `src_ip` | Exact IP address |
| Dst IP | `dst_ip` | Exact IP address |
| Dst Port | `dst_port` | Exact port number |
| Src Port | `src_port` | Exact port number |
| Protocol | `proto` | tcp, udp, icmp |
| File Path | `file_path` | Partial match on file path |
| Registry Key | `reg_key` | Partial match on registry key path |
| Channel | `channel` | Windows event log channel (Security, System, etc.) |
| Event ID | `event_id` | Windows Event ID (numeric) |
| Min Severity | `severity` | Minimum severity level (1–5) |
| Free Text | `search` | Searches across host, user, process, command line, IPs, paths |
| Host | `host` | Partial match on hostname |
| Agent ID | `agent_id` | Exact agent UUID |
| Since / Until | `since`, `until` | ISO 8601 time range |

All text fields use case-insensitive partial matching (ILIKE). Multiple filters are ANDed together.

---

## 100 Saved Queries Reference

### Process Execution (20 queries)

| # | Query | What it finds |
|---|---|---|
| 1 | All PowerShell executions | Every powershell.exe process event |
| 2 | PowerShell encoded commands | `-EncodedCommand` / `-enc` flags — obfuscated scripts |
| 3 | PowerShell download cradles | `DownloadString`, `IEX`, `WebClient` — remote code execution |
| 4 | CMD suspicious execution | cmd.exe with recon or abuse commands |
| 5 | Rundll32 executions | Living-off-the-land binary abuse |
| 6 | MSHTA executions | HTML Application host — initial access vector |
| 7 | WScript/CScript executions | Windows Script Host — VBScript/JScript malware |
| 8 | Regsvr32 executions | Squiblydoo AppLocker bypass |
| 9 | Certutil abuse | Download and encode/decode with certutil.exe |
| 10 | BITSAdmin executions | BITS background transfer abuse |
| 11 | Scheduled task creation | Persistence via schtasks.exe |
| 12 | New service creation | Persistence via sc.exe |
| 13 | PsExec remote execution | Remote command execution tool |
| 14 | All high-severity process events | Severity ≥ 4 process events |
| 15 | Net.exe account commands | User and group enumeration |
| 16 | whoami execution | Recon after initial compromise |
| 17 | Windows Scripting Host (cscript) | Alternative script execution |
| 18 | Shadow copy deletion (vssadmin) | Ransomware pre-cursor |
| 19 | bcdedit — recovery disabled | Boot recovery disabled — ransomware indicator |
| 20 | WMIC command execution | Windows Management Instrumentation abuse |

### Credential Access (10 queries)

| # | Query | What it finds |
|---|---|---|
| 21 | Failed logon events (4625) | Authentication failures — brute force indicator |
| 22 | Successful logon events (4624) | All successful authentications |
| 23 | Logon with explicit credentials (4648) | `runas` or `net use` with credentials |
| 24 | LSASS access attempts | Credential dumping attempts |
| 25 | Mimikatz indicators | Mimikatz usage by name |
| 26 | Procdump usage | LSASS dump via Sysinternals procdump |
| 27 | SAM registry access | SAM hive access — password hash theft |
| 28 | Credential file search | findstr/grep for "password" strings |
| 29 | All high-severity logon events | Severity ≥ 4 logon events |
| 30 | Logoff events (4634) | Session terminations |

### Network Activity (15 queries)

| # | Query | What it finds |
|---|---|---|
| 31 | All outbound RDP (3389) | Remote Desktop Protocol connections |
| 32 | All outbound SMB (445) | File shares, lateral movement, ransomware |
| 33 | All outbound SSH (22) | SSH from Windows — unusual |
| 34 | Outbound FTP (21) | Data exfiltration via FTP |
| 35 | HTTP outbound (80) | Unencrypted web traffic |
| 36 | HTTPS outbound (443) | Encrypted web traffic |
| 37 | DNS queries (53) | All DNS traffic |
| 38 | SMTP outbound (587) | Email sending |
| 39 | High-severity network events | Severity ≥ 4 network events |
| 40 | All TCP connections | TCP protocol filter |
| 41 | All UDP traffic | UDP protocol filter |
| 42 | WinRM (5985/5986) | Remote management — lateral movement |
| 43 | LDAP traffic (389) | Active Directory queries |
| 44 | Kerberos (88) | Kerberos authentication traffic |
| 45 | Database ports (1433) | SQL Server connections |

### DNS Queries (10 queries)

| # | Query | What it finds |
|---|---|---|
| 46 | All DNS events | Every DNS query captured |
| 47 | RustDesk DNS queries | RustDesk remote access tool |
| 48 | WPAD proxy discovery | Web Proxy Auto-Discovery — MITM risk |
| 49 | Urban VPN queries | Browser VPN extension |
| 50 | ngrok tunnel queries | Ngrok tunnel — C2 or data exfiltration |
| 51 | Pastebin DNS lookups | Command and control via Pastebin |
| 52 | TOR-related DNS | .onion domains |
| 53 | AnyDesk DNS queries | AnyDesk remote access |
| 54 | TeamViewer DNS queries | TeamViewer remote access |
| 55 | High-severity DNS events | Severity ≥ 4 DNS events |

### File Activity (10 queries)

| # | Query | What it finds |
|---|---|---|
| 56 | All file events | Every file system event captured |
| 57 | Temp directory writes | Files written to TEMP — dropper activity |
| 58 | AppData writes | Files written to AppData |
| 59 | Desktop file drops | Files dropped on Desktop |
| 60 | Executable files written (.exe) | New executables created |
| 61 | Script files written (.ps1) | New PowerShell scripts created |
| 62 | Startup folder writes | Persistence via Startup folder |
| 63 | System32 writes | System directory tampering |
| 64 | Encrypted file extensions | Files renamed to .locked, .encrypted |
| 65 | High-severity file events | Severity ≥ 4 file events |

### Registry (10 queries)

| # | Query | What it finds |
|---|---|---|
| 66 | All registry events | Every registry change captured |
| 67 | Run key modifications | `CurrentVersion\Run` — persistence |
| 68 | RunOnce key modifications | `RunOnce` — one-time persistence |
| 69 | Security policy registry changes | `Policies` hive modifications |
| 70 | Service registry modifications | `Services` hive — new service installs |
| 71 | LSA registry modifications | LSA provider changes — credential theft prep |
| 72 | Winlogon key modifications | Winlogon — login hijacking |
| 73 | AppInit DLLs modifications | DLL injection via AppInit |
| 74 | IE Zone settings | Zone security bypass |
| 75 | High-severity registry events | Severity ≥ 4 registry events |

### User Activity (10 queries)

| # | Query | What it finds |
|---|---|---|
| 76 | All events for admin user | Every event attributed to admin |
| 77 | All events for SYSTEM account | SYSTEM-level activity |
| 78 | Guest account activity | Guest account usage — should be disabled |
| 79 | Network service account | NETWORK SERVICE activity |
| 80 | Events with no user context | Anonymous or system-context events |
| 81 | All user logon events | All logon events across all users |
| 82 | High-severity user events | Severity ≥ 4 across any user |
| 83 | Service account logons | Accounts containing "svc" |
| 84 | Interactive logons (Type 2) | Console/RDP logons via Event 4624 |
| 85 | Account management (4720) | New account creation events |

### Sysmon & Advanced (15 queries)

| # | Query | What it finds |
|---|---|---|
| 86 | All Sysmon events | Every Sysmon-sourced event |
| 87 | Sysmon process creation (ID 1) | Process creation with full telemetry |
| 88 | Sysmon network connection (ID 3) | Network connections with process context |
| 89 | Sysmon file creation (ID 11) | File create events |
| 90 | Sysmon registry event (ID 12) | Registry create/delete |
| 91 | Sysmon image loaded (ID 7) | DLL load events |
| 92 | Sysmon process access (ID 10) | Process access (LSASS dump detection) |
| 93 | All critical severity events | Severity = 5 across all types |
| 94 | All high severity events | Severity ≥ 4 across all types |
| 95 | Windows Security channel | Security event log events |
| 96 | Windows System channel | System event log events |
| 97 | PowerShell Operational channel | PowerShell script block logging |
| 98 | Event log cleared (1102) | Security log cleared |
| 99 | AppLocker block events (8004) | AppLocker blocked executions |
| 100 | All raw events | Unclassified / raw agent events |

---

## Threat Detection Library

The Detection Engine runs as a background goroutine every **45 seconds**, scanning recent events against 35+ threat signatures. Each match generates a new alert with the MITRE ATT&CK technique ID in the title.

Detections are deduplicated — the same event can only trigger each signature once. Email notifications fire automatically if SMTP is configured and the signature severity meets `min_severity`.

View all active signatures in the **Detections** page of the dashboard.

### Signature Index

#### Execution

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1059.001 | PowerShell Encoded Command | High (4) | `-enc` or `-encodedcommand` in PowerShell command line |
| T1059.001b | PowerShell Download Cradle | Critical (5) | `downloadstring`, `iex(`, `webclient`, `wget` in PowerShell |
| T1059.003 | Suspicious CMD Execution | Medium (3) | cmd.exe running whoami, net, ipconfig, certutil, bitsadmin |
| T1218.011 | Rundll32 Suspicious Execution | High (4) | rundll32 with javascript:, http, or shell32 |
| T1218.005 | MSHTA Execution | High (4) | Any mshta.exe process event |
| T1218.010 | Regsvr32 Bypass | Critical (5) | regsvr32 with /u /s and http or scrobj.dll |
| T1059.005 | WScript/CScript Execution | Medium (3) | Any wscript.exe or cscript.exe process |

#### Discovery

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1057 | Process Discovery | Low (2) | tasklist, Get-Process, qprocess in command line |
| T1016 | Network Configuration Discovery | Low (2) | ipconfig, netstat, arp -a, route print |
| T1087 | Account Enumeration | Medium (3) | net user, net group, Get-ADUser, whoami /all |
| T1083 | Sensitive Directory Enumeration | Low (2) | dir on Users/AppData/Temp, Get-ChildItem |

#### Privilege Escalation

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1548.002 | UAC Bypass Attempt | Critical (5) | eventvwr, fodhelper, sdclt, bypassuac in command line |
| T1055 | Process Injection Indicator | Critical (5) | VirtualAlloc, WriteProcessMemory, CreateRemoteThread, mimikatz |

#### Credential Access

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1003.001 | LSASS Memory Dump | Critical (5) | lsass + procdump or comsvcs.dll,MiniDump |
| T1003.002 | SAM Database Access | Critical (5) | SAM registry key or `reg save hklm\sam` |
| T1552.001 | Credentials in Files Search | Medium (3) | findstr for password, .kdbx files, unattend.xml |
| T1110 | Brute Force — Failed Logons | Medium (3) | Windows Event ID 4625 (failed logon) |

#### Lateral Movement

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1021.001 | RDP Lateral Movement | High (4) | Outbound network to port 3389 |
| T1021.002 | SMB Lateral Movement | High (4) | Outbound network to port 445 |
| T1021.004 | SSH Lateral Movement | Medium (3) | Outbound network to port 22 |
| T1570 | PsExec / Remote Execution | High (4) | psexec, paexec, wmiexec, winrm in process name/cmdline |

#### Persistence

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1547.001 | Run Key Persistence | High (4) | Registry write to `CurrentVersion\Run` or `RunOnce` |
| T1053.005 | Scheduled Task Created | Medium (3) | schtasks /create, New-ScheduledTask, at.exe |
| T1543.003 | New Service Created | High (4) | sc create, New-Service, or Services registry write |

#### Defence Evasion

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1562.001 | Security Tool Disabled | Critical (5) | Windows Defender disable, firewall off, sc stop windefend |
| T1070.001 | Event Log Cleared | Critical (5) | Event ID 1102/104, wevtutil cl, Clear-EventLog |
| T1027 | Obfuscated Command | High (4) | frombase64string, [convert]::, char(, backtick obfuscation |
| T1036 | Process Name Masquerading | High (4) | System process (svchost, lsass) running outside system32 |

#### Command & Control

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1219 | Remote Access Tool — RustDesk | High (4) | rustdesk in DNS/process |
| T1219b | Remote Access Tool — AnyDesk/TV | Medium (3) | anydesk, teamviewer, screenconnect in process/path |
| T1572 | DNS Tunnelling Indicator | High (4) | DNS hostname longer than 60 characters |
| T1071.001b | Suspicious Outbound Port | Medium (3) | Connection to non-standard port > 1024 |
| T1090 | WPAD Proxy Discovery | Medium (3) | DNS query for "wpad" |

#### Exfiltration

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1048 | Data Exfiltration — FTP | High (4) | Outbound to port 21 (FTP) |
| T1041 | Certutil Encode/Decode | High (4) | certutil with -encode, -decode, or -urlcache |

#### Impact

| ID | Signature | Severity | Trigger |
|---|---|---|---|
| T1490 | Shadow Copy Deletion | Critical (5) | vssadmin delete shadows, wmic shadowcopy delete, bcdedit recoveryenabled No |
| T1486 | Mass File Modification | Critical (5) | File events with .locked, .encrypted, .crypto extensions |

---

## Tuning & Extending Detections

Signatures are defined in `backend/internal/api/detection_engine.go`. Each signature is a Go struct with a `Match` function that receives a full `Event` object. Adding a new signature:

```go
{
    ID: "T1234.001", Name: "My Detection",
    Description: "What this detects and why it matters.",
    Severity: 4, MITRE: "T1234.001", Category: "Execution",
    Match: func(ev store.Event) bool {
        return ev.EventType == "process" && containsAny(cl(ev), "suspicious-string")
    },
},
```

Helper functions available inside `Match`:
- `cl(ev)` — lowercased command line
- `proc(ev)` — lowercased process name
- `img(ev)` — lowercased image path
- `fp(ev)` — lowercased file path
- `rk(ev)` — lowercased registry key
- `dstip(ev)` — lowercased destination IP/hostname
- `containsAny(s, sub1, sub2, ...)` — true if `s` contains any substring

After adding signatures, rebuild the container:
```bash
sudo docker compose up -d --build
```

---

## Severity Reference

| Level | Label | Meaning | Auto-email default |
|---|---|---|---|
| 1 | Info | Informational — normal activity | No |
| 2 | Low | Unusual but not immediately dangerous | No |
| 3 | Medium | Suspicious — warrants investigation | No |
| 4 | High | Likely malicious — investigate promptly | Yes (if min_severity=4) |
| 5 | Critical | Active threat — respond immediately | Yes |

