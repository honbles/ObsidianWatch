package store

// db.go — local SQLite state for the network probe.
// Stores: device inventory, flow baselines, ARP table, bandwidth history.
// All raw syslog/netflow data stays here — only summaries go up.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	db *sql.DB
	mu sync.RWMutex
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000&_fk=true")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	d := &DB{db: db}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

func (d *DB) migrate() error {
	_, err := d.db.Exec(`
	CREATE TABLE IF NOT EXISTS devices (
		mac         TEXT PRIMARY KEY,
		ip          TEXT NOT NULL DEFAULT '',
		hostname    TEXT NOT NULL DEFAULT '',
		vendor      TEXT NOT NULL DEFAULT '',
		first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		is_known    INTEGER NOT NULL DEFAULT 0,
		device_type TEXT NOT NULL DEFAULT '',  -- router|switch|ap|server|workstation|unknown
		os_guess    TEXT NOT NULL DEFAULT '',
		location    TEXT NOT NULL DEFAULT '',
		extra       TEXT NOT NULL DEFAULT '{}'  -- JSON extra fields
	);

	CREATE TABLE IF NOT EXISTS flows (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ts          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		src_ip      TEXT NOT NULL,
		dst_ip      TEXT NOT NULL,
		src_port    INTEGER NOT NULL DEFAULT 0,
		dst_port    INTEGER NOT NULL DEFAULT 0,
		proto       TEXT NOT NULL DEFAULT '',
		bytes       INTEGER NOT NULL DEFAULT 0,
		packets     INTEGER NOT NULL DEFAULT 0,
		duration_ms INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_flows_ts     ON flows (ts);
	CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows (src_ip, ts);

	CREATE TABLE IF NOT EXISTS bandwidth_hourly (
		hour        DATETIME NOT NULL,
		src_ip      TEXT NOT NULL,
		bytes_out   INTEGER NOT NULL DEFAULT 0,
		bytes_in    INTEGER NOT NULL DEFAULT 0,
		packets_out INTEGER NOT NULL DEFAULT 0,
		packets_in  INTEGER NOT NULL DEFAULT 0,
		flow_count  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (hour, src_ip)
	);

	CREATE TABLE IF NOT EXISTS snmp_stats (
		ts          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		host        TEXT NOT NULL,
		iface       TEXT NOT NULL DEFAULT '',
		bytes_in    INTEGER NOT NULL DEFAULT 0,
		bytes_out   INTEGER NOT NULL DEFAULT 0,
		errors_in   INTEGER NOT NULL DEFAULT 0,
		errors_out  INTEGER NOT NULL DEFAULT 0,
		cpu_pct     REAL NOT NULL DEFAULT 0,
		mem_pct     REAL NOT NULL DEFAULT 0,
		uptime_sec  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ts, host, iface)
	);

	CREATE TABLE IF NOT EXISTS arp_table (
		ip          TEXT NOT NULL,
		mac         TEXT NOT NULL,
		iface       TEXT NOT NULL DEFAULT '',
		first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (ip, mac)
	);

	CREATE TABLE IF NOT EXISTS port_scan_tracker (
		src_ip      TEXT NOT NULL,
		dst_ip      TEXT NOT NULL,
		window_start DATETIME NOT NULL,
		port_count  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (src_ip, dst_ip, window_start)
	);

	CREATE TABLE IF NOT EXISTS brute_force_tracker (
		src_ip      TEXT NOT NULL,
		dst_ip      TEXT NOT NULL,
		proto       TEXT NOT NULL DEFAULT '',
		window_start DATETIME NOT NULL,
		fail_count  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (src_ip, dst_ip, proto, window_start)
	);

	CREATE TABLE IF NOT EXISTS topology (
		local_host  TEXT NOT NULL,
		local_iface TEXT NOT NULL DEFAULT '',
		neighbor    TEXT NOT NULL,
		neighbor_ip TEXT NOT NULL DEFAULT '',
		proto       TEXT NOT NULL DEFAULT '', -- cdp | lldp
		updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (local_host, local_iface, neighbor)
	);
	`)
	return err
}

// ── Device Inventory ──────────────────────────────────────────────────────────

type Device struct {
	MAC        string
	IP         string
	Hostname   string
	Vendor     string
	FirstSeen  time.Time
	LastSeen   time.Time
	IsKnown    bool
	DeviceType string
	OSGuess    string
	Location   string
}

func (d *DB) UpsertDevice(ctx context.Context, dev Device) (isNew bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var count int
	d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE mac=$1`, dev.MAC).Scan(&count)
	isNew = count == 0
	_, err = d.db.ExecContext(ctx, `
		INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, device_type, os_guess)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(mac) DO UPDATE SET
			ip=excluded.ip, hostname=COALESCE(NULLIF(excluded.hostname,''), hostname),
			vendor=COALESCE(NULLIF(excluded.vendor,''), vendor),
			last_seen=excluded.last_seen,
			device_type=COALESCE(NULLIF(excluded.device_type,''), device_type),
			os_guess=COALESCE(NULLIF(excluded.os_guess,''), os_guess)`,
		dev.MAC, dev.IP, dev.Hostname, dev.Vendor,
		dev.FirstSeen, dev.LastSeen, dev.DeviceType, dev.OSGuess)
	return
}

func (d *DB) GetAllDevices(ctx context.Context) ([]Device, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rows, err := d.db.QueryContext(ctx, `
		SELECT mac, ip, hostname, vendor, first_seen, last_seen, is_known, device_type, os_guess, location
		FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devs []Device
	for rows.Next() {
		var dev Device
		var isKnown int
		rows.Scan(&dev.MAC, &dev.IP, &dev.Hostname, &dev.Vendor,
			&dev.FirstSeen, &dev.LastSeen, &isKnown, &dev.DeviceType, &dev.OSGuess, &dev.Location)
		dev.IsKnown = isKnown == 1
		devs = append(devs, dev)
	}
	return devs, nil
}

// ── Flow Recording ────────────────────────────────────────────────────────────

type Flow struct {
	SrcIP      string
	DstIP      string
	SrcPort    int
	DstPort    int
	Proto      string
	Bytes      int64
	Packets    int64
	DurationMS int64
	Time       time.Time
}

func (d *DB) InsertFlow(ctx context.Context, f Flow) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.ExecContext(ctx, `
		INSERT INTO flows (ts, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets, duration_ms)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		f.Time, f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.Proto, f.Bytes, f.Packets, f.DurationMS)
	return err
}

func (d *DB) RollupHourlyBandwidth(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.ExecContext(ctx, `
		INSERT INTO bandwidth_hourly (hour, src_ip, bytes_out, packets_out, flow_count)
		SELECT
			strftime('%Y-%m-%d %H:00:00', ts) as hour,
			src_ip,
			SUM(bytes) as bytes_out,
			SUM(packets) as packets_out,
			COUNT(*) as flow_count
		FROM flows
		WHERE ts >= datetime('now', '-2 hours') AND ts < datetime('now', '-1 hour')
		GROUP BY hour, src_ip
		ON CONFLICT(hour, src_ip) DO UPDATE SET
			bytes_out=excluded.bytes_out, packets_out=excluded.packets_out, flow_count=excluded.flow_count`)
	return err
}

func (d *DB) GetTopTalkers(ctx context.Context, hours int, limit int) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rows, err := d.db.QueryContext(ctx, `
		SELECT src_ip, SUM(bytes_out) as total_bytes, SUM(flow_count) as total_flows
		FROM bandwidth_hourly
		WHERE hour >= datetime('now', $1)
		GROUP BY src_ip ORDER BY total_bytes DESC LIMIT $2`,
		fmt.Sprintf("-%d hours", hours), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var srcIP string
		var bytes, flows int64
		rows.Scan(&srcIP, &bytes, &flows)
		out = append(out, map[string]interface{}{
			"src_ip": srcIP, "total_bytes": bytes, "total_flows": flows,
		})
	}
	return out, nil
}

// ── ARP Table ─────────────────────────────────────────────────────────────────

func (d *DB) UpsertARP(ctx context.Context, ip, mac, iface string) (macChanged bool, oldMAC string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Check for MAC change (ARP spoofing indicator)
	d.db.QueryRowContext(ctx, `SELECT mac FROM arp_table WHERE ip=$1 AND mac!=$2 LIMIT 1`, ip, mac).Scan(&oldMAC)
	macChanged = oldMAC != ""
	_, err = d.db.ExecContext(ctx, `
		INSERT INTO arp_table (ip, mac, iface) VALUES ($1,$2,$3)
		ON CONFLICT(ip, mac) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, iface=excluded.iface`,
		ip, mac, iface)
	return
}

func (d *DB) GetARPTable(ctx context.Context) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rows, err := d.db.QueryContext(ctx, `
		SELECT a.ip, a.mac, a.iface, a.first_seen, a.last_seen,
		       COALESCE(d.hostname,'') as hostname, COALESCE(d.vendor,'') as vendor
		FROM arp_table a
		LEFT JOIN devices d ON d.mac = a.mac
		ORDER BY a.last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var ip, mac, iface, hostname, vendor string
		var firstSeen, lastSeen time.Time
		rows.Scan(&ip, &mac, &iface, &firstSeen, &lastSeen, &hostname, &vendor)
		out = append(out, map[string]interface{}{
			"ip": ip, "mac": mac, "iface": iface,
			"first_seen": firstSeen, "last_seen": lastSeen,
			"hostname": hostname, "vendor": vendor,
		})
	}
	return out, nil
}

// ── Port Scan Detection ───────────────────────────────────────────────────────

func (d *DB) TrackPortScan(ctx context.Context, srcIP, dstIP string, windowSec int) (portCount int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	window := time.Now().UTC().Truncate(time.Duration(windowSec) * time.Second)
	d.db.ExecContext(ctx, `
		INSERT INTO port_scan_tracker (src_ip, dst_ip, window_start, port_count)
		VALUES ($1,$2,$3,1)
		ON CONFLICT(src_ip,dst_ip,window_start) DO UPDATE SET port_count=port_count+1`,
		srcIP, dstIP, window)
	d.db.QueryRowContext(ctx, `
		SELECT port_count FROM port_scan_tracker WHERE src_ip=$1 AND dst_ip=$2 AND window_start=$3`,
		srcIP, dstIP, window).Scan(&portCount)
	return
}

// ── Brute Force Detection ─────────────────────────────────────────────────────

func (d *DB) TrackAuthFailure(ctx context.Context, srcIP, dstIP, proto string, windowSec int) (failCount int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	window := time.Now().UTC().Truncate(time.Duration(windowSec) * time.Second)
	d.db.ExecContext(ctx, `
		INSERT INTO brute_force_tracker (src_ip, dst_ip, proto, window_start, fail_count)
		VALUES ($1,$2,$3,$4,1)
		ON CONFLICT(src_ip,dst_ip,proto,window_start) DO UPDATE SET fail_count=fail_count+1`,
		srcIP, dstIP, proto, window)
	d.db.QueryRowContext(ctx, `
		SELECT fail_count FROM brute_force_tracker WHERE src_ip=$1 AND dst_ip=$2 AND proto=$3 AND window_start=$4`,
		srcIP, dstIP, proto, window).Scan(&failCount)
	return
}

// ── Topology ──────────────────────────────────────────────────────────────────

func (d *DB) UpsertTopology(ctx context.Context, localHost, localIface, neighbor, neighborIP, proto string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.ExecContext(ctx, `
		INSERT INTO topology (local_host, local_iface, neighbor, neighbor_ip, proto)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT(local_host,local_iface,neighbor) DO UPDATE SET
			neighbor_ip=excluded.neighbor_ip, proto=excluded.proto, updated_at=CURRENT_TIMESTAMP`,
		localHost, localIface, neighbor, neighborIP, proto)
	return err
}

func (d *DB) GetTopology(ctx context.Context) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rows, err := d.db.QueryContext(ctx, `
		SELECT local_host, local_iface, neighbor, neighbor_ip, proto, updated_at
		FROM topology ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var localHost, localIface, neighbor, neighborIP, proto string
		var updatedAt time.Time
		rows.Scan(&localHost, &localIface, &neighbor, &neighborIP, &proto, &updatedAt)
		out = append(out, map[string]interface{}{
			"local_host": localHost, "local_iface": localIface,
			"neighbor": neighbor, "neighbor_ip": neighborIP,
			"proto": proto, "updated_at": updatedAt,
		})
	}
	return out, nil
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

func (d *DB) Cleanup(ctx context.Context, retentionDays int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := fmt.Sprintf("-%d days", retentionDays)
	d.db.ExecContext(ctx, `DELETE FROM flows WHERE ts < datetime('now', $1)`, cutoff)
	d.db.ExecContext(ctx, `DELETE FROM bandwidth_hourly WHERE hour < datetime('now', $1)`, cutoff)
	d.db.ExecContext(ctx, `DELETE FROM snmp_stats WHERE ts < datetime('now', $1)`, cutoff)
	d.db.ExecContext(ctx, `DELETE FROM port_scan_tracker WHERE window_start < datetime('now', $1)`, cutoff)
	d.db.ExecContext(ctx, `DELETE FROM brute_force_tracker WHERE window_start < datetime('now', $1)`, cutoff)
}

// OUI vendor lookup (first 3 bytes of MAC → vendor name)
var ouiMap = map[string]string{
	"00:50:56": "VMware", "00:0c:29": "VMware",
	"00:1a:a0": "Dell", "f8:db:88": "Dell",
	"3c:5a:b4": "Google", "54:ee:75": "Apple",
	"00:1b:63": "Apple", "00:17:f2": "Apple",
	"00:1c:bf": "Cisco", "00:1e:49": "Cisco",
	"00:90:27": "Intel", "00:23:14": "Intel",
	"b8:27:eb": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi",
	"00:1a:11": "Google Nest", "f4:f5:d8": "Google",
	"dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
	"00:e0:4c": "Realtek",
	"44:85:00": "Fortinet", "00:09:0f": "Fortinet",
	"00:1b:17": "Palo Alto",
	"00:1c:7f": "Palo Alto",
}

func VendorFromMAC(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 3 {
		return ""
	}
	oui := fmt.Sprintf("%02x:%02x:%02x", hw[0], hw[1], hw[2])
	return ouiMap[oui]
}

// MarshalJSON helper
func ToJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ── Analysis query methods ────────────────────────────────────────────────────

// GetTopDestinations returns the most-connected destination IPs in the last N hours
func (d *DB) GetTopDestinations(ctx context.Context, hours int, limit int) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rows, err := d.db.QueryContext(ctx, `
		SELECT dst_ip, dst_port, proto,
		       SUM(bytes) as total_bytes, COUNT(*) as flow_count
		FROM flows
		WHERE ts >= datetime('now', $1)
		  AND dst_ip != '' AND dst_ip NOT LIKE '192.168.%'
		  AND dst_ip NOT LIKE '10.%' AND dst_ip NOT LIKE '172.%'
		GROUP BY dst_ip, dst_port, proto
		ORDER BY total_bytes DESC LIMIT $2`,
		fmt.Sprintf("-%d hours", hours), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var dstIP, proto string
		var dstPort int
		var bytes, flows int64
		rows.Scan(&dstIP, &dstPort, &proto, &bytes, &flows)
		out = append(out, map[string]interface{}{
			"dst_ip": dstIP, "dst_port": dstPort, "proto": proto,
			"total_bytes": bytes, "flow_count": flows,
		})
	}
	return out, nil
}

// GetAuthFailureSummary returns auth failure counts per src/dst in last N minutes
func (d *DB) GetAuthFailureSummary(ctx context.Context, minutes int) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rows, err := d.db.QueryContext(ctx, `
		SELECT src_ip, dst_ip as dst_device, proto,
		       SUM(fail_count) as fail_count
		FROM brute_force_tracker
		WHERE window_start >= datetime('now', $1)
		GROUP BY src_ip, dst_ip, proto
		ORDER BY fail_count DESC LIMIT 20`,
		fmt.Sprintf("-%d minutes", minutes))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var srcIP, dst, proto string
		var count int64
		rows.Scan(&srcIP, &dst, &proto, &count)
		out = append(out, map[string]interface{}{
			"src_ip": srcIP, "dst_device": dst,
			"proto": proto, "fail_count": count,
		})
	}
	return out, nil
}

// GetRecentlyOfflineDevices returns devices seen recently but not in the last N minutes
func (d *DB) GetRecentlyOfflineDevices(ctx context.Context, offlineMinutes, activeHours int) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	rows, err := d.db.QueryContext(ctx, `
		SELECT mac, ip, hostname, vendor, last_seen
		FROM devices
		WHERE last_seen < datetime('now', $1)
		  AND last_seen > datetime('now', $2)
		ORDER BY last_seen DESC LIMIT 50`,
		fmt.Sprintf("-%d minutes", offlineMinutes),
		fmt.Sprintf("-%d hours", activeHours))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var mac, ip, hostname, vendor string
		var lastSeen time.Time
		rows.Scan(&mac, &ip, &hostname, &vendor, &lastSeen)
		out = append(out, map[string]interface{}{
			"mac": mac, "ip": ip, "hostname": hostname,
			"vendor": vendor, "last_seen": lastSeen,
		})
	}
	return out, nil
}

// GetTopFirewallDenies returns the most-blocked source IPs from syslog events
func (d *DB) GetTopFirewallDenies(ctx context.Context, minutes, limit int) ([]map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	// We use the port_scan_tracker as a proxy for repeated denies
	// In a fuller implementation this would query a syslog_events table
	rows, err := d.db.QueryContext(ctx, `
		SELECT src_ip, dst_ip, SUM(port_count) as deny_count
		FROM port_scan_tracker
		WHERE window_start >= datetime('now', $1)
		GROUP BY src_ip, dst_ip
		ORDER BY deny_count DESC LIMIT $2`,
		fmt.Sprintf("-%d minutes", minutes), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var srcIP, dstIP string
		var count int64
		rows.Scan(&srcIP, &dstIP, &count)
		out = append(out, map[string]interface{}{
			"src_ip": srcIP, "dst_ip": dstIP, "deny_count": count,
		})
	}
	return out, nil
}
