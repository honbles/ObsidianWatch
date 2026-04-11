package store

import (
	"context"
	"fmt"
	"time"
)

type StatPoint struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
}

// EventsOverTime returns event counts bucketed by hour for the last N hours.
func (db *DB) EventsOverTime(ctx context.Context, hours int) ([]StatPoint, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT time_bucket('1 hour', time) AS bucket, COUNT(*) as count
		FROM events
		WHERE time > NOW() - ($1 || ' hours')::INTERVAL
		GROUP BY bucket
		ORDER BY bucket ASC
	`, hours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []StatPoint
	for rows.Next() {
		var p StatPoint
		if err := rows.Scan(&p.Time, &p.Count); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// EventsBySeverity returns event counts grouped by severity for last 24h.
func (db *DB) EventsBySeverity(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT severity, COUNT(*) as count
		FROM events
		WHERE time > NOW() - INTERVAL '24 hours'
		GROUP BY severity
		ORDER BY severity
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	labels := map[int]string{1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
	var result []map[string]interface{}
	for rows.Next() {
		var sev int
		var count int64
		rows.Scan(&sev, &count)
		result = append(result, map[string]interface{}{
			"severity": sev,
			"label":    labels[sev],
			"count":    count,
		})
	}
	return result, rows.Err()
}

// EventsByType returns event counts grouped by event_type for last 24h.
func (db *DB) EventsByType(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT event_type, COUNT(*) as count
		FROM events
		WHERE time > NOW() - INTERVAL '24 hours'
		GROUP BY event_type
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var evType string
		var count int64
		rows.Scan(&evType, &count)
		result = append(result, map[string]interface{}{
			"event_type": evType,
			"count":      count,
		})
	}
	return result, rows.Err()
}

// Summary returns top-level counts for the dashboard header.
func (db *DB) Summary(ctx context.Context) (map[string]interface{}, error) {
	var totalEvents, eventsToday, highSeverityToday int64

	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&totalEvents)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE time > NOW() - INTERVAL '24 hours'`).Scan(&eventsToday)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE severity >= 4 AND time > NOW() - INTERVAL '24 hours'`).Scan(&highSeverityToday)

	var totalAgents, onlineAgents int64
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents`).Scan(&totalAgents)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE last_seen > NOW() - INTERVAL '2 minutes'`).Scan(&onlineAgents)

	var openAlerts int64
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE status = 'open'`).Scan(&openAlerts)

	return map[string]interface{}{
		"total_events":        totalEvents,
		"events_today":        eventsToday,
		"high_severity_today": highSeverityToday,
		"total_agents":        totalAgents,
		"online_agents":       onlineAgents,
		"open_alerts":         openAlerts,
	}, nil
}

// ThreatIntel returns DNS domain query counts, top source IPs, top processes, top users.
func (db *DB) ThreatIntel(ctx context.Context) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	// Top queried DNS domains
	rows, err := db.QueryContext(ctx, `
		SELECT raw->>'query_name' as domain, COUNT(*) as count
		FROM events
		WHERE source = 'DNS-Client'
		  AND raw->>'query_name' IS NOT NULL
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY raw->>'query_name'
		ORDER BY count DESC
		LIMIT 20
	`)
	if err == nil {
		var domains []map[string]interface{}
		for rows.Next() {
			var domain string
			var count int64
			rows.Scan(&domain, &count)
			domains = append(domains, map[string]interface{}{"domain": domain, "count": count})
		}
		rows.Close()
		result["top_domains"] = domains
	}

	// Top source IPs
	rows, err = db.QueryContext(ctx, `
		SELECT src_ip, COUNT(*) as count
		FROM events
		WHERE src_ip IS NOT NULL AND src_ip != ''
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY src_ip
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		var ips []map[string]interface{}
		for rows.Next() {
			var ip string
			var count int64
			rows.Scan(&ip, &count)
			ips = append(ips, map[string]interface{}{"ip": ip, "count": count})
		}
		rows.Close()
		result["top_src_ips"] = ips
	}

	// Top destination IPs
	rows, err = db.QueryContext(ctx, `
		SELECT dst_ip, COUNT(*) as count
		FROM events
		WHERE dst_ip IS NOT NULL AND dst_ip != ''
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY dst_ip
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		var ips []map[string]interface{}
		for rows.Next() {
			var ip string
			var count int64
			rows.Scan(&ip, &count)
			ips = append(ips, map[string]interface{}{"ip": ip, "count": count})
		}
		rows.Close()
		result["top_dst_ips"] = ips
	}

	// Top processes
	rows, err = db.QueryContext(ctx, `
		SELECT process_name, COUNT(*) as count
		FROM events
		WHERE process_name IS NOT NULL
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY process_name
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		var procs []map[string]interface{}
		for rows.Next() {
			var proc string
			var count int64
			rows.Scan(&proc, &count)
			procs = append(procs, map[string]interface{}{"process": proc, "count": count})
		}
		rows.Close()
		result["top_processes"] = procs
	}

	// Top users
	rows, err = db.QueryContext(ctx, `
		SELECT user_name, COUNT(*) as count
		FROM events
		WHERE user_name IS NOT NULL AND user_name != ''
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY user_name
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		var users []map[string]interface{}
		for rows.Next() {
			var user string
			var count int64
			rows.Scan(&user, &count)
			users = append(users, map[string]interface{}{"user": user, "count": count})
		}
		rows.Close()
		result["top_users"] = users
	}

	// Flagged domains — domains globally that match IOC blocklist categories
	// (Quad9/SURBL/Spamhaus — replaces old hardcoded keyword list)
	flaggedRows, flaggedErr := db.QueryContext(ctx, `
		SELECT e.dst_ip as domain,
		       COUNT(*) as count,
		       i.tags as categories,
		       i.severity as ioc_severity
		FROM events e
		INNER JOIN ioc_indicators i
		       ON i.ioc_type = 'domain_category'
		      AND i.value = LOWER(e.dst_ip)
		      AND (i.expires_at IS NULL OR i.expires_at > NOW())
		      AND i.tags != 'clean'
		WHERE e.event_type = 'dns'
		  AND e.dst_ip IS NOT NULL
		  AND e.time > NOW() - INTERVAL '24 hours'
		GROUP BY e.dst_ip, i.tags, i.severity
		ORDER BY i.severity DESC, count DESC
		LIMIT 20
	`)
	if flaggedErr == nil {
		var flagged []map[string]interface{}
		for flaggedRows.Next() {
			var domain, categories string
			var count, sev int64
			flaggedRows.Scan(&domain, &count, &categories, &sev)
			flagged = append(flagged, map[string]interface{}{
				"domain": domain, "count": count,
				"categories": categories, "ioc_severity": sev,
			})
		}
		flaggedRows.Close()
		result["flagged_domains"] = flagged
	}

	return result, nil
}

// ThreatIntelHost returns threat intel scoped to a specific host.
func (db *DB) ThreatIntelHost(ctx context.Context, host string, hours int) (map[string]interface{}, error) {
	result := map[string]interface{}{"host": host, "hours": hours}
	interval := fmt.Sprintf("%d hours", hours)

	run := func(q string, args ...interface{}) ([]map[string]interface{}, error) {
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil { return nil, err }
		defer rows.Close()
		cols, _ := rows.Columns()
		var out []map[string]interface{}
		for rows.Next() {
			vals := make([]interface{}, len(cols))
			ptrs := make([]interface{}, len(cols))
			for i := range vals { ptrs[i] = &vals[i] }
			rows.Scan(ptrs...)
			row := map[string]interface{}{}
			for i, c := range cols { row[c] = vals[i] }
			out = append(out, row)
		}
		return out, nil
	}

	// Top DNS domains with persistence tracking (first seen, last seen, days seen)
	if rows, err := run(`
		SELECT dst_ip as domain,
		       COUNT(*) as count,
		       MIN(time) as first_seen,
		       MAX(time) as last_seen,
		       COUNT(DISTINCT DATE(time)) as days_seen,
		       COUNT(DISTINCT DATE(time)) > 7 as persistent
		FROM events
		WHERE host ILIKE $1 AND event_type = 'dns'
		  AND dst_ip IS NOT NULL AND dst_ip != ''
		  AND time > NOW() - ($2 || ' hours')::interval
		GROUP BY dst_ip ORDER BY count DESC LIMIT 25
	`, "%"+host+"%", interval); err == nil { result["top_domains"] = rows }

	// NEW domains — first seen in this window (not seen before)
	if rows, err := run(`
		SELECT dst_ip as domain, COUNT(*) as count, MIN(time) as first_seen
		FROM events
		WHERE host ILIKE $1 AND event_type = 'dns'
		  AND dst_ip IS NOT NULL AND dst_ip != ''
		  AND time > NOW() - ($2 || ' hours')::interval
		  AND dst_ip NOT IN (
		    SELECT DISTINCT dst_ip FROM events
		    WHERE host ILIKE $1 AND event_type = 'dns'
		      AND dst_ip IS NOT NULL
		      AND time < NOW() - ($2 || ' hours')::interval
		      AND time > NOW() - INTERVAL '30 days'
		  )
		GROUP BY dst_ip ORDER BY count DESC LIMIT 10
	`, "%"+host+"%", interval); err == nil { result["new_domains"] = rows }

	// Top destination IPs/ports
	if rows, err := run(`
		SELECT dst_ip, dst_port, proto, COUNT(*) as count
		FROM events
		WHERE host ILIKE $1 AND event_type = 'network'
		  AND dst_ip IS NOT NULL AND dst_ip != ''
		  AND time > NOW() - ($2 || ' hours')::interval
		GROUP BY dst_ip, dst_port, proto ORDER BY count DESC LIMIT 20
	`, "%"+host+"%", interval); err == nil { result["top_connections"] = rows }

	// Top processes by event count
	if rows, err := run(`
		SELECT process_name, COUNT(*) as count, MAX(severity) as max_severity
		FROM events
		WHERE host ILIKE $1
		  AND process_name IS NOT NULL AND process_name != ''
		  AND time > NOW() - ($2 || ' hours')::interval
		GROUP BY process_name ORDER BY count DESC LIMIT 20
	`, "%"+host+"%", interval); err == nil { result["top_processes"] = rows }

	// Top users
	if rows, err := run(`
		SELECT user_name, COUNT(*) as count, MAX(severity) as max_severity
		FROM events
		WHERE host ILIKE $1
		  AND user_name IS NOT NULL AND user_name != ''
		  AND time > NOW() - ($2 || ' hours')::interval
		GROUP BY user_name ORDER BY count DESC LIMIT 15
	`, "%"+host+"%", interval); err == nil { result["top_users"] = rows }

	// Top registry keys
	if rows, err := run(`
		SELECT COALESCE(NULLIF(reg_key,''), raw->>'key', raw->>'TargetObject') as reg_key,
		       COUNT(*) as count
		FROM events
		WHERE host ILIKE $1 AND event_type = 'registry'
		  AND time > NOW() - ($2 || ' hours')::interval
		  AND COALESCE(NULLIF(reg_key,''), raw->>'key', raw->>'TargetObject') IS NOT NULL
		GROUP BY 1 ORDER BY count DESC LIMIT 15
	`, "%"+host+"%", interval); err == nil { result["top_registry"] = rows }

	// Top file paths
	if rows, err := run(`
		SELECT COALESCE(NULLIF(file_path,''), raw->>'path') as file_path,
		       COUNT(*) as count
		FROM events
		WHERE host ILIKE $1 AND event_type = 'file'
		  AND time > NOW() - ($2 || ' hours')::interval
		  AND COALESCE(NULLIF(file_path,''), raw->>'path') IS NOT NULL
		GROUP BY 1 ORDER BY count DESC LIMIT 15
	`, "%"+host+"%", interval); err == nil { result["top_files"] = rows }

	// High severity events
	if rows, err := run(`
		SELECT id, time, event_type, severity, source,
		       COALESCE(NULLIF(process_name,''), '') as process_name,
		       COALESCE(NULLIF(command_line,''), '') as command_line,
		       COALESCE(NULLIF(dst_ip,''), '') as dst_ip,
		       COALESCE(NULLIF(file_path,''), raw->>'path', '') as file_path
		FROM events
		WHERE host ILIKE $1 AND severity >= 3
		  AND time > NOW() - ($2 || ' hours')::interval
		ORDER BY severity DESC, time DESC LIMIT 30
	`, "%"+host+"%", interval); err == nil { result["high_severity"] = rows }

	// Event type summary
	if rows, err := run(`
		SELECT event_type, COUNT(*) as count, MAX(severity) as max_severity
		FROM events
		WHERE host ILIKE $1
		  AND time > NOW() - ($2 || ' hours')::interval
		GROUP BY event_type ORDER BY count DESC
	`, "%"+host+"%", interval); err == nil { result["event_types"] = rows }

	// Timeline (hourly buckets)
	if rows, err := run(`
		SELECT date_trunc('hour', time) as hour, COUNT(*) as count
		FROM events
		WHERE host ILIKE $1
		  AND time > NOW() - ($2 || ' hours')::interval
		GROUP BY 1 ORDER BY 1
	`, "%"+host+"%", interval); err == nil { result["timeline"] = rows }

	// Active alerts for this host
	if rows, err := run(`
		SELECT id, created_at, title, severity, status, event_type, source_event_id
		FROM alerts
		WHERE host ILIKE $1
		  AND status = 'open'
		  AND created_at > NOW() - ($2 || ' hours')::interval
		ORDER BY severity DESC, created_at DESC
		LIMIT 20
	`, "%"+host+"%", interval); err == nil { result["active_alerts"] = rows }

	// IOC matches — events from this host that matched ThreatFox/OTX indicators
	if rows, err := run(`
		SELECT DISTINCT
		       a.title,
		       a.severity,
		       a.created_at,
		       a.event_type,
		       e.dst_ip,
		       e.dst_port,
		       e.process_name,
		       e.file_hash
		FROM alerts a
		LEFT JOIN events e ON e.id = a.source_event_id
		WHERE a.host ILIKE $1
		  AND a.created_at > NOW() - ($2 || ' hours')::interval
		  AND (a.title LIKE '%%IOC Match%%' OR a.title LIKE '%%ThreatFox%%' OR a.title LIKE '%%OTX%%')
		ORDER BY a.severity DESC, a.created_at DESC
		LIMIT 20
	`, "%"+host+"%", interval); err == nil { result["ioc_matches"] = rows }

	// DNS category flags — domains this host resolved that are in IOC category lists
	// (from Quad9/SURBL/Spamhaus via dns_categorization engine)
	if rows, err := run(`
		SELECT e.dst_ip as domain,
		       COUNT(*) as query_count,
		       i.tags as categories,
		       i.severity as ioc_severity,
		       i.source as ioc_source
		FROM events e
		INNER JOIN ioc_indicators i
		       ON i.ioc_type = 'domain_category'
		      AND i.value = LOWER(e.dst_ip)
		      AND (i.expires_at IS NULL OR i.expires_at > NOW())
		      AND i.tags != 'clean'
		WHERE e.host ILIKE $1
		  AND e.event_type = 'dns'
		  AND e.dst_ip IS NOT NULL
		  AND e.time > NOW() - ($2 || ' hours')::interval
		GROUP BY e.dst_ip, i.tags, i.severity, i.source
		ORDER BY i.severity DESC, query_count DESC
		LIMIT 20
	`, "%"+host+"%", interval); err == nil { result["dns_category_flags"] = rows }

	// Also replace the old hardcoded suspicious domain query with IOC-backed one
	// Flagged IPs — network connections to known malicious IPs
	if rows, err := run(`
		SELECT DISTINCT
		       e.dst_ip,
		       e.dst_port,
		       e.proto,
		       COUNT(*) as connection_count,
		       i.malware,
		       i.threat_type,
		       i.severity as ioc_severity,
		       i.source as ioc_source
		FROM events e
		INNER JOIN ioc_indicators i
		       ON i.ioc_type = 'ip'
		      AND i.value = LOWER(e.dst_ip)
		      AND (i.expires_at IS NULL OR i.expires_at > NOW())
		WHERE e.host ILIKE $1
		  AND e.event_type = 'network'
		  AND e.dst_ip IS NOT NULL
		  AND e.time > NOW() - ($2 || ' hours')::interval
		GROUP BY e.dst_ip, e.dst_port, e.proto, i.malware, i.threat_type, i.severity, i.source
		ORDER BY i.severity DESC, connection_count DESC
		LIMIT 20
	`, "%"+host+"%", interval); err == nil { result["flagged_ips"] = rows }

	// Flagged domains — DNS queries to known malicious domains (OTX/ThreatFox)
	if rows, err := run(`
		SELECT DISTINCT
		       e.dst_ip as domain,
		       COUNT(*) as query_count,
		       i.malware,
		       i.threat_type,
		       i.severity as ioc_severity,
		       i.source as ioc_source
		FROM events e
		INNER JOIN ioc_indicators i
		       ON i.ioc_type = 'domain'
		      AND LOWER(i.value) = LOWER(e.dst_ip)
		      AND (i.expires_at IS NULL OR i.expires_at > NOW())
		WHERE e.host ILIKE $1
		  AND e.event_type = 'dns'
		  AND e.dst_ip IS NOT NULL
		  AND e.time > NOW() - ($2 || ' hours')::interval
		GROUP BY e.dst_ip, i.malware, i.threat_type, i.severity, i.source
		ORDER BY i.severity DESC, query_count DESC
		LIMIT 20
	`, "%"+host+"%", interval); err == nil { result["flagged_domains"] = rows }

	// Flagged hashes — file events with hashes matching OTX/ThreatFox IOCs
	if rows, err := run(`
		SELECT DISTINCT
		       e.file_hash as hash,
		       e.file_path,
		       e.process_name,
		       COUNT(*) as hit_count,
		       i.malware,
		       i.threat_type,
		       i.severity as ioc_severity,
		       i.source as ioc_source
		FROM events e
		INNER JOIN ioc_indicators i
		       ON i.ioc_type = 'hash'
		      AND LOWER(i.value) = LOWER(e.file_hash)
		      AND (i.expires_at IS NULL OR i.expires_at > NOW())
		WHERE e.host ILIKE $1
		  AND e.event_type = 'file'
		  AND e.file_hash IS NOT NULL
		  AND e.time > NOW() - ($2 || ' hours')::interval
		GROUP BY e.file_hash, e.file_path, e.process_name, i.malware, i.threat_type, i.severity, i.source
		ORDER BY i.severity DESC, hit_count DESC
		LIMIT 20
	`, "%"+host+"%", interval); err == nil { result["flagged_hashes"] = rows }

	return result, nil
}

// DashboardStats returns enriched stats for the new interactive dashboard.
func (db *DB) DashboardStats(ctx context.Context) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	run := func(q string, args ...interface{}) []map[string]interface{} {
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil { return nil }
		defer rows.Close()
		cols, _ := rows.Columns()
		var out []map[string]interface{}
		for rows.Next() {
			vals := make([]interface{}, len(cols))
			ptrs := make([]interface{}, len(cols))
			for i := range vals { ptrs[i] = &vals[i] }
			rows.Scan(ptrs...)
			row := map[string]interface{}{}
			for i, c := range cols { row[c] = vals[i] }
			out = append(out, row)
		}
		return out
	}

	// Per-host event counts + last event time + max severity in 24h
	result["hosts_activity"] = run(`
		SELECT host, COUNT(*) as event_count,
		       MAX(severity) as max_severity,
		       MAX(time) as last_event
		FROM events
		WHERE time > NOW() - INTERVAL '24 hours'
		GROUP BY host ORDER BY event_count DESC LIMIT 20
	`)

	// Recent open alerts with severity
	result["recent_alerts"] = run(`
		SELECT id, title, severity, status, host, created_at
		FROM alerts
		WHERE status = 'open'
		ORDER BY severity DESC, created_at DESC
		LIMIT 10
	`)

	// Top processes generating events (last 24h)
	result["top_processes"] = run(`
		SELECT process_name, COUNT(*) as count, MAX(severity) as max_severity,
		       host
		FROM events
		WHERE process_name IS NOT NULL AND process_name != ''
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY process_name, host
		ORDER BY max_severity DESC, count DESC
		LIMIT 15
	`)

	// Top DNS domains (last 24h)
	result["top_domains"] = run(`
		SELECT dst_ip as domain, COUNT(*) as count, host
		FROM events
		WHERE event_type = 'dns' AND dst_ip IS NOT NULL AND dst_ip != ''
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY dst_ip, host
		ORDER BY count DESC LIMIT 15
	`)

	// Critical/High events last 24h (for feed)
	result["threat_feed"] = run(`
		SELECT id, time, host, event_type, severity, source,
		       COALESCE(NULLIF(process_name,''),'') as process_name,
		       COALESCE(NULLIF(command_line,''),'') as command_line,
		       COALESCE(NULLIF(dst_ip,''),'') as dst_ip,
		       COALESCE(NULLIF(file_path,''), raw->>'path', '') as file_path
		FROM events
		WHERE severity >= 3
		  AND time > NOW() - INTERVAL '24 hours'
		ORDER BY severity DESC, time DESC
		LIMIT 50
	`)

	// Events per hour for last 48h broken out by severity band
	result["timeline_48h"] = run(`
		SELECT date_trunc('hour', time) as hour,
		       COUNT(*) FILTER (WHERE severity >= 4) as high,
		       COUNT(*) FILTER (WHERE severity = 3) as medium,
		       COUNT(*) FILTER (WHERE severity <= 2) as low
		FROM events
		WHERE time > NOW() - INTERVAL '48 hours'
		GROUP BY 1 ORDER BY 1
	`)

	// Agent health
	result["agents"] = run(`
		SELECT id, hostname, os, last_ip,
		       (last_seen > NOW() - INTERVAL '2 minutes') as online,
		       last_seen, version
		FROM agents ORDER BY hostname
	`)

	// Event type counts
	result["by_type"] = run(`
		SELECT event_type, COUNT(*) as count
		FROM events WHERE time > NOW() - INTERVAL '24 hours'
		GROUP BY event_type ORDER BY count DESC
	`)


	// Top countries by outbound connection IPs (last 24h) — excludes private ranges
	result["top_countries"] = run(`
		SELECT dst_ip as country, COUNT(*) as count
		FROM events
		WHERE event_type = 'network'
		  AND dst_ip IS NOT NULL AND dst_ip != ''
		  AND dst_ip NOT LIKE '192.168.%'
		  AND dst_ip NOT LIKE '10.%'
		  AND dst_ip NOT LIKE '127.%'
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY dst_ip
		ORDER BY count DESC LIMIT 10
	`)

	// Malicious IPs — from alerts with IOC type
	result["malicious_ips"] = run(`
		SELECT DISTINCT host, title, description, created_at
		FROM alerts
		WHERE (title ILIKE '%malicious ip%' OR title ILIKE '%IOC%' OR title ILIKE '%virustotal%' OR title ILIKE '%CIRCL%')
		  AND created_at > NOW() - INTERVAL '24 hours'
		ORDER BY created_at DESC LIMIT 10
	`)

	// Malicious domains — from alerts
	result["malicious_domains"] = run(`
		SELECT DISTINCT host, title, description, created_at
		FROM alerts
		WHERE (title ILIKE '%domain%' OR title ILIKE '%dns%' OR title ILIKE '%blocklist%')
		  AND created_at > NOW() - INTERVAL '24 hours'
		ORDER BY created_at DESC LIMIT 10
	`)

	// Malicious files — hash alerts
	result["malicious_files"] = run(`
		SELECT DISTINCT host, title, description, created_at
		FROM alerts
		WHERE (title ILIKE '%hash%' OR title ILIKE '%malicious file%' OR title ILIKE '%CIRCL%' OR title ILIKE '%VIRUSTOTAL%')
		  AND created_at > NOW() - INTERVAL '24 hours'
		ORDER BY created_at DESC LIMIT 10
	`)

	// Detection rules count
	var detectionRules int64
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM detection_signatures WHERE enabled IS TRUE OR enabled = true`).Scan(&detectionRules)
	result["detection_rules_active"] = detectionRules

	// DevOps overview
	result["devops_overview"] = run(`
		SELECT dc.provider, dc.org,
		       COALESCE(sr.repo_count, 0) as repos_scanned,
		       COALESCE(sr.finding_count, 0) as findings,
		       COALESCE(sr.critical_count, 0) as critical
		FROM devops_connectors dc
		LEFT JOIN (
		    SELECT connector_id,
		           COUNT(DISTINCT repo) as repo_count,
		           SUM(finding_count) as finding_count,
		           SUM(critical_count) as critical_count
		    FROM sast_results
		    GROUP BY connector_id
		) sr ON sr.connector_id = dc.id
		ORDER BY dc.id
	`)

	return result, nil
}
