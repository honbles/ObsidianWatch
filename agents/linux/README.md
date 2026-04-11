# ObsidianWatch Linux Agent

Security event collection agent for Linux systems. Sends events to the ObsidianWatch backend.

## What It Collects

| Collector | Mechanism | Events |
|-----------|-----------|--------|
| **Process** | Netlink proc connector (`CN_IDX_PROC`) | Every fork/exec/exit with PID, PPID, cmdline, exe path, username |
| **Network** | `/proc/net/tcp,tcp6,udp,udp6` poll | New connections with src/dst IP+port, PID, process name |
| **FIM** | inotify | File create/modify/delete/rename in `/etc`, `/bin`, `/usr/bin`, `/tmp` and more |
| **Audit** | auditd log tail | Execve, sudo, login/logout, user management, crashes |
| **Journald** | `journalctl -f` | SSH login/fail, sudo, PAM auth, kernel OOM, service failures |
| **AppLog** | File tail | Configurable application log files (nginx, apache, etc.) |
| **Health** | Go ticker | Heartbeat with uptime, memory, active collectors |

## Requirements

- Linux kernel ≥ 3.2 (inotify + netlink proc connector)
- Root / CAP_NET_ADMIN for process connector
- `auditd` installed for audit log collection (optional but recommended)
- `journalctl` for journal collection (optional, falls back to auth.log)

## Quick Start

### Interactive (test mode)
```bash
# Edit the config first
cp configs/agent.yaml agent.yaml
# Set backend_url and api_key

sudo ./agent -config agent.yaml
```

### Install as systemd service
```bash
sudo ./agent -config agent.yaml install
# You will be prompted for a tamper protection password
```

### Check status
```bash
sudo ./agent status
# or
sudo systemctl status obsidianwatch-agent
sudo journalctl -u obsidianwatch-agent -f
```

### Uninstall
```bash
sudo ./agent -config agent.yaml uninstall
# You will be prompted for the tamper protection password
```

## Build

```bash
# Build for the current system
go build -o agent ./cmd/agent/

# Cross-compile for Linux AMD64 from any OS
GOOS=linux GOARCH=amd64 go build -o agent-linux-amd64 ./cmd/agent/

# ARM64 (Raspberry Pi, AWS Graviton)
GOOS=linux GOARCH=arm64 go build -o agent-linux-arm64 ./cmd/agent/
```

## Configuration

Edit `configs/agent.yaml`:

```yaml
forwarder:
  backend_url: "https://YOUR_SERVER:8443"
  management_url: "http://YOUR_SERVER"
  api_key: "changeme"
  ca_file: "certs/ca.crt"   # copy from backend/certs/
```

## Tamper Protection

When installed as a service:
- Binary and config are owned by root (mode 700/600)
- systemd `ProtectSystem=strict` prevents non-root modification
- Uninstall requires the password set at install time (verified against the management server)
- Password appears on the ObsidianWatch dashboard: Agents → shield icon

## Installed Locations

| Path | Purpose |
|------|---------|
| `/opt/obsidianwatch/` | Binary + config (root-only) |
| `/var/lib/obsidianwatch/` | Event queue (SQLite) |
| `/etc/systemd/system/obsidianwatch-agent.service` | systemd unit |

## Recommended: Enable auditd

For the best process and login visibility:

```bash
# Ubuntu/Debian
sudo apt install auditd
sudo systemctl enable auditd --now

# RHEL/CentOS/Rocky
sudo yum install audit
sudo systemctl enable auditd --now
```

The agent will automatically pick up auditd logs from `/var/log/audit/audit.log`.
