# ObsidianWatch Network Probe

A network intelligence sensor that sits inside your network, collects telemetry from all network devices, and sends only analysed summaries and alerts to the ObsidianWatch management server.

**Raw logs never leave your network.** All analysis runs locally on the probe.

---

## Architecture

```
Network Devices (Cisco / Palo Alto / Fortinet / any device)
    │
    │  Syslog UDP/TCP :514       ← devices push logs to probe
    │  NetFlow/IPFIX UDP :2055   ← routers push flow records to probe
    │  sFlow UDP :6343           ← switches push flow samples to probe
    ▼
┌──────────────────────────────────────────────┐
│          Network Probe (Go binary)            │
│                                               │
│  Collectors:                                  │
│    • Syslog listener  → parses + detects      │
│    • NetFlow receiver → flow analysis         │
│    • SNMP poller      → device health + ARP   │
│    • ARP monitor      → /proc/net/arp         │
│                                               │
│  Local SQLite database:                       │
│    • Device inventory (MAC, IP, vendor)       │
│    • Flow records (src, dst, bytes, ports)    │
│    • Bandwidth history (hourly rollups)       │
│    • ARP table history                        │
│    • Auth failure counts                      │
│    • Port scan tracking                       │
│                                               │
│  Analysis engine (every 5 min):               │
│    • Queries SQLite                           │
│    • Detects: port scans, brute force,        │
│      lateral movement, bandwidth spikes,      │
│      ARP spoofing, new devices                │
│    • Sends summaries + alerts only ↑          │
└──────────────────────────────────────────────┘
    │  HTTPS → Management Server
    │  Sends:
    │    • Alerts (threats detected)
    │    • Device inventory (every 5 min)
    │    • Bandwidth summaries (top talkers)
    │    • Firewall deny summaries
    │    • Device health (SNMP)
    ▼
Management Server (cloud or on-prem)
```

---

## Installation

### 1. Download from Agent Builder

In the ObsidianWatch management dashboard:
1. Go to **Agent Builder**
2. Fill in **Backend URL**, **Management URL**, **API Key**, and **Site Name**
3. Click **Build** under **Network Probe**
4. Download the zip, extract, copy binary to the probe host

### 2. Install on the probe host

The probe host is any Linux machine (VM, bare metal, Raspberry Pi) that:
- Has network access to all devices you want to monitor
- Is reachable on port 514 (syslog) and 2055 (NetFlow) from network devices
- Has SNMP access to network devices (port 161 outbound)

**Quick install:**
```bash
# Copy binary to probe host, then:
sudo ./obsidianwatch-network-probe install --site "HQ-Network" --subnet 192.168.1.0/24

# Start the service
sudo systemctl enable --now obsidianwatch-probe

# Watch logs
journalctl -u obsidianwatch-probe -f
```

**Install with SNMP auto-discovery:**
```bash
sudo ./obsidianwatch-network-probe install \
  --site "Branch-Office" \
  --subnet 10.10.0.0/24 \
  --community public
```
This scans `10.10.0.0/24` for SNMP devices and adds them to the config automatically.

**Discover devices without installing:**
```bash
sudo ./obsidianwatch-network-probe discover --subnet 192.168.1.0/24 --community public
```

---

## Configuration

Config file location: `/etc/obsidianwatch-probe/probe.yaml`

Edit after install, restart to apply:
```bash
sudo nano /etc/obsidianwatch-probe/probe.yaml
sudo systemctl restart obsidianwatch-probe
```

### Key sections

```yaml
probe:
  site_name: "HQ-Network"     # Shows in management dashboard
  location:  "Server Room"    # Physical location label

forwarder:
  backend_url:    "https://192.168.1.140:8443"   # ← REQUIRED
  management_url: "http://192.168.1.140"          # ← REQUIRED
  api_key:        "your-api-key-here"             # ← REQUIRED

syslog:
  enabled:  true
  udp_addr: ":514"   # All devices point their syslog here

netflow:
  enabled: true
  addr:    ":2055"   # Routers send NetFlow here

snmp:
  enabled:       true
  poll_interval: "60s"
  # Option A: explicit targets
  targets:
    - host:      "192.168.1.1"
      version:   "v2c"
      community: "public"
      label:     "core-router"
  # Option B: auto-discover on startup
  auto_discover:
    subnet:    "192.168.1.0/24"
    community: "public"

arp:
  enabled:    true
  interfaces: ["eth0"]   # Interface on the monitored network
```

### SNMP v3 (recommended for security)
```yaml
snmp:
  targets:
    - host:       "192.168.1.1"
      version:    "v3"
      username:   "obsidianwatch"
      auth_proto: "SHA"
      auth_key:   "your-auth-passphrase"
      priv_proto: "AES"
      priv_key:   "your-priv-passphrase"
      label:      "core-router"
```

---

## Configuring Network Devices

### Cisco IOS / IOS-XE — Syslog
```
conf t
logging host 192.168.1.50          ! probe IP
logging trap informational
logging on
end
```

### Cisco IOS — NetFlow
```
conf t
ip flow-export destination 192.168.1.50 2055
ip flow-export version 9
interface GigabitEthernet0/0
  ip flow ingress
  ip flow egress
end
```

### Cisco ASA — Syslog
```
logging host inside 192.168.1.50
logging trap informational
logging enable
```

### Palo Alto — Syslog
1. Device → Server Profiles → Syslog → Add
2. Name: `obsidianwatch`, Server: `<probe-ip>`, Port: `514`, Transport: UDP
3. Objects → Log Forwarding → Add → select Syslog profile
4. Apply to security policies

### Fortinet FortiGate — Syslog
```
config log syslogd setting
  set status enable
  set server "192.168.1.50"
  set port 514
  set facility local7
  set format default
end
```

### Fortinet — NetFlow
```
config system netflow
  set collector-ip "192.168.1.50"
  set collector-port 2055
  set active-flow-timeout 60
end
```

### pfSense — Syslog
Status → System Logs → Settings → Enable Remote Logging
Remote log servers: `192.168.1.50:514`

### MikroTik — Syslog
```
/system logging action
add name=obsidianwatch target=remote remote=192.168.1.50 remote-port=514

/system logging
add action=obsidianwatch topics=firewall,info,warning,error
```

### Generic Linux/BSD (rsyslog) — Forward syslog
Add to `/etc/rsyslog.conf`:
```
*.* @192.168.1.50:514   # UDP
*.* @@192.168.1.50:514  # TCP
```

---

## What the probe detects (locally)

| Detection | Mechanism | Threshold |
|---|---|---|
| Port scan | NetFlow: distinct ports/min per src→dst | 20 ports/60s |
| Brute force | Syslog auth failures | 10 failures/60s |
| ARP spoofing | MAC change for same IP | Any change |
| New device | DHCP lease, NetFlow src, ARP | First seen |
| Bandwidth spike | NetFlow vs EMA baseline | 3× baseline |
| Lateral movement | East-west NetFlow on SMB/RDP/SSH | First connection |
| Config change | Syslog pattern match | Any |
| Interface down | Syslog pattern match | Any |
| VPN at odd hours | Syslog VPN event time | Before 06:00 or after 22:00 UTC |
| SNMP unreachable | SNMP poll timeout | 3 consecutive failures |

---

## What gets sent to management

| Data | Frequency | Size |
|---|---|---|
| Alerts (threats) | Immediately | Small — text only |
| Device inventory | Every 5 min | ~1KB per device |
| Top talkers bandwidth | Every 5 min | ~2KB |
| Firewall deny summary | Every 5 min | ~1KB |
| Device health (SNMP) | Every 60s | ~500B per device |
| Auth failure summary | Every 5 min | ~1KB |

**Raw syslog, raw NetFlow records, and raw SNMP walks are never sent.**

---

## Troubleshooting

### Probe not receiving syslog
```bash
# Check if port 514 is open and listening
ss -ulnp | grep 514
# Test send a syslog message
logger -n 192.168.1.50 -P 514 "test message from $(hostname)"
# Watch probe logs
journalctl -u obsidianwatch-probe -f | grep syslog
```

### SNMP not working
```bash
# Test SNMP manually from probe host
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.5.0
# Check firewall allows UDP 161 outbound from probe
```

### Probe not appearing in management
```bash
# Check forwarder config
cat /etc/obsidianwatch-probe/probe.yaml | grep -A5 forwarder
# Test connectivity to backend
curl -k https://192.168.1.140:8443/health
# Check probe logs for send errors
journalctl -u obsidianwatch-probe | grep "send failed"
```

### Restart after config change
```bash
sudo systemctl restart obsidianwatch-probe
journalctl -u obsidianwatch-probe -f
```
