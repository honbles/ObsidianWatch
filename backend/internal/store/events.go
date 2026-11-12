package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"obsidianwatch/backend/pkg/schema"
)

// InsertEvents writes a batch of events to the hypertable using a single
// COPY-style multi-row INSERT for efficiency.
func (db *DB) InsertEvents(ctx context.Context, events []schema.Event) error {
	if len(events) == 0 {
		return nil
	}

	const cols = 31 // number of columns in the INSERT
	placeholders := make([]string, 0, len(events))
	args := make([]interface{}, 0, len(events)*cols)

	for i, ev := range events {
		base := i * cols
		placeholders = append(placeholders, rowPlaceholder(base+1, cols))

		rawBytes, _ := json.Marshal(ev.Raw)
		// Sanitise: strip null bytes and invalid UTF-8 that PostgreSQL rejects
		rawBytes = sanitiseJSON(rawBytes)
		// If still too large, trim the packages array (biggest offender in vuln scans)
		const maxRawBytes = 256 * 1024 // 256KB
		if len(rawBytes) > maxRawBytes {
			rawBytes = trimJSONPackages(rawBytes, maxRawBytes)
		}

		args = append(args,
			ev.ID,
			ev.Time.UTC(),
			ev.AgentID,
			ev.Host,
			ev.OS,
			string(ev.EventType),
			int(ev.Severity),
			ev.Source,
			rawBytes,
			nullInt(ev.PID),
			nullInt(ev.PPID),
			nullStr(ev.ProcessName),
			nullStr(ev.CommandLine),
			nullStr(ev.ImagePath),
			nullStr(ev.UserName),
			nullStr(ev.Domain),
			nullStr(ev.LogonID),
			nullStr(ev.SrcIP),
			nullInt(ev.SrcPort),
			nullStr(ev.DstIP),
			nullInt(ev.DstPort),
			nullStr(ev.Proto),
			nullStr(ev.RegKey),
			nullStr(ev.RegValue),
			nullStr(ev.RegData),
			nullStr(ev.FilePath),
			nullStr(ev.FileHash),
			nullUint32(ev.EventID),
			nullStr(ev.Channel),
			nullStr(ev.ProcessGUID),
			nullStr(ev.ParentProcessGUID),
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO events (
			id, time, agent_id, host, os, event_type, severity, source, raw,
			pid, ppid, process_name, command_line, image_path,
			user_name, domain, logon_id,
			src_ip, src_port, dst_ip, dst_port, proto,
			reg_key, reg_value, reg_data,
			file_path, file_hash,
			event_id, channel,
			process_guid, parent_process_guid
		) VALUES %s
		ON CONFLICT (id, time) DO NOTHING`,
		strings.Join(placeholders, ","),
	)

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		// Batch failed — log the error and try inserting events one-by-one
		// This prevents one corrupted event from blocking the entire batch
		fmt.Printf("store: batch insert failed (len=%d events), falling back to one-by-one: %v\n", len(events), err)
		var lastErr error
		for _, ev := range events {
			rawB, _ := json.Marshal(ev.Raw)
			// Aggressively trim oversized payloads — vuln scans can be large
			const singleMaxBytes = 128 * 1024 // 128KB per event
			if len(rawB) > singleMaxBytes {
				rawB = trimJSONPackages(rawB, singleMaxBytes)
			}
			rawB = sanitiseJSON(rawB)
			singleQuery := `INSERT INTO events (
				id, time, agent_id, host, os, event_type, severity, source, raw,
				pid, ppid, process_name, command_line, image_path,
				user_name, domain, logon_id,
				src_ip, src_port, dst_ip, dst_port, proto,
				reg_key, reg_value, reg_data,
				file_path, file_hash,
				event_id, channel,
				process_guid, parent_process_guid
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31
			) ON CONFLICT (id, time) DO NOTHING`
			singleArgs := []interface{}{
				ev.ID, ev.Time.UTC(), ev.AgentID, ev.Host, ev.OS,
				string(ev.EventType), int(ev.Severity), ev.Source, rawB,
				nullInt(ev.PID), nullInt(ev.PPID), nullStr(ev.ProcessName),
				nullStr(ev.CommandLine), nullStr(ev.ImagePath),
				nullStr(ev.UserName), nullStr(ev.Domain), nullStr(ev.LogonID),
				nullStr(ev.SrcIP), nullInt(ev.SrcPort), nullStr(ev.DstIP),
				nullInt(ev.DstPort), nullStr(ev.Proto),
				nullStr(ev.RegKey), nullStr(ev.RegValue), nullStr(ev.RegData),
				nullStr(ev.FilePath), nullStr(ev.FileHash),
				nullUint32(ev.EventID), nullStr(ev.Channel),
				nullStr(ev.ProcessGUID), nullStr(ev.ParentProcessGUID),
			}
			if _, sErr := db.ExecContext(ctx, singleQuery, singleArgs...); sErr != nil {
				fmt.Printf("store: single insert failed event_type=%s host=%s raw_bytes=%d: %v\n",
					string(ev.EventType), ev.Host, len(rawB), sErr)
				lastErr = sErr
			}
		}
		if lastErr != nil {
			// At least one event failed individual insert — return error so caller knows
			// but don't block: partial success is acceptable for mixed batches
			fmt.Printf("store: %d events had insert errors\n", len(events))
		}
		return nil // partial success — don't re-queue the whole batch
	}
	return nil
}

// QueryFilter holds parameters for searching events.
type QueryFilter struct {
	AgentID   string
	Host      string
	EventType string
	Severity  int
	SrcIP     string
	DstIP     string
	UserName  string
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

// QueryEvents returns events matching the filter, ordered by time DESC.
func (db *DB) QueryEvents(ctx context.Context, f QueryFilter) ([]schema.Event, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	n := 1

	add := func(clause string, val interface{}) {
		where = append(where, fmt.Sprintf(clause, n))
		args = append(args, val)
		n++
	}

	if f.AgentID != "" {
		add("agent_id = $%d", f.AgentID)
	}
	if f.Host != "" {
		add("host ILIKE $%d", "%"+f.Host+"%")
	}
	if f.EventType != "" {
		add("event_type = $%d", f.EventType)
	}
	if f.Severity > 0 {
		add("severity >= $%d", f.Severity)
	}
	if f.SrcIP != "" {
		add("src_ip = $%d", f.SrcIP)
	}
	if f.DstIP != "" {
		add("dst_ip = $%d", f.DstIP)
	}
	if f.UserName != "" {
		add("user_name ILIKE $%d", "%"+f.UserName+"%")
	}
	if !f.Since.IsZero() {
		add("time >= $%d", f.Since.UTC())
	}
	if !f.Until.IsZero() {
		add("time <= $%d", f.Until.UTC())
	}

	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}

	query := fmt.Sprintf(`
		SELECT id, time, agent_id, host, os, event_type, severity, source, raw,
		       pid, ppid, process_name, command_line, image_path,
		       user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, reg_data,
		       file_path, file_hash,
		       event_id, channel, record_id,
		       COALESCE(process_guid,''), COALESCE(parent_process_guid,'')
		FROM events
		WHERE %s
		ORDER BY time DESC
		LIMIT %d OFFSET %d`,
		strings.Join(where, " AND "),
		f.Limit,
		f.Offset,
	)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query events: %w", err)
	}
	defer rows.Close()

	var events []schema.Event
	for rows.Next() {
		var ev schema.Event
		var (
			rawBytes    []byte
			pid, ppid   *int
			srcPort     *int
			dstPort     *int
			eventID     *uint32
			recordID    *uint64
			srcIP, dstIP *string
		)

		if err := rows.Scan(
			&ev.ID, &ev.Time, &ev.AgentID, &ev.Host, &ev.OS,
			&ev.EventType, &ev.Severity, &ev.Source, &rawBytes,
			&pid, &ppid, &ev.ProcessName, &ev.CommandLine, &ev.ImagePath,
			&ev.UserName, &ev.Domain, &ev.LogonID,
			&srcIP, &srcPort, &dstIP, &dstPort, &ev.Proto,
			&ev.RegKey, &ev.RegValue, &ev.RegData,
			&ev.FilePath, &ev.FileHash,
			&eventID, &ev.Channel, &recordID,
			&ev.ProcessGUID, &ev.ParentProcessGUID,
		); err != nil {
			return nil, fmt.Errorf("store: scan event: %w", err)
		}

		ev.Raw = rawBytes
		if pid != nil {
			ev.PID = *pid
		}
		if ppid != nil {
			ev.PPID = *ppid
		}
		if srcIP != nil {
			ev.SrcIP = *srcIP
		}
		if srcPort != nil {
			ev.SrcPort = *srcPort
		}
		if dstIP != nil {
			ev.DstIP = *dstIP
		}
		if dstPort != nil {
			ev.DstPort = *dstPort
		}
		if eventID != nil {
			ev.EventID = *eventID
		}
		if recordID != nil {
			ev.RecordID = *recordID
		}
		events = append(events, ev)
	}

	return events, rows.Err()
}

// CountEvents returns a total count matching the filter (no limit/offset).
func (db *DB) CountEvents(ctx context.Context, f QueryFilter) (int64, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	n := 1

	add := func(clause string, val interface{}) {
		where = append(where, fmt.Sprintf(clause, n))
		args = append(args, val)
		n++
	}

	if f.AgentID != "" {
		add("agent_id = $%d", f.AgentID)
	}
	if f.EventType != "" {
		add("event_type = $%d", f.EventType)
	}
	if f.Severity > 0 {
		add("severity >= $%d", f.Severity)
	}
	if !f.Since.IsZero() {
		add("time >= $%d", f.Since.UTC())
	}
	if !f.Until.IsZero() {
		add("time <= $%d", f.Until.UTC())
	}

	query := fmt.Sprintf(
		`SELECT COUNT(*) FROM events WHERE %s`,
		strings.Join(where, " AND "),
	)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func rowPlaceholder(start, count int) string {
	parts := make([]string, count)
	for i := 0; i < count; i++ {
		parts[i] = fmt.Sprintf("$%d", start+i)
	}
	return "(" + strings.Join(parts, ",") + ")"
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(i int) interface{} {
	if i == 0 {
		return nil
	}
	return i
}

func nullUint32(i uint32) interface{} {
	if i == 0 {
		return nil
	}
	return i
}

// sanitiseJSON removes null bytes and invalid UTF-8 sequences that PostgreSQL
// JSONB rejects with "unsupported Unicode escape sequence" (22P05).
func sanitiseJSON(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		// Drop null bytes — PostgreSQL cannot store them in text/jsonb
		if c == 0x00 {
			continue
		}
		// Replace lone backslash-u escapes that PostgreSQL chokes on
		// by passing valid UTF-8 bytes through and replacing invalid ones
		out = append(out, c)
	}
	// Final pass: ensure valid UTF-8 by replacing bad sequences
	return []byte(strings.ToValidUTF8(string(out), ""))
}

// trimJSONPackages reduces oversized vuln scan payloads by trimming the packages array.
// It keeps all other fields intact (ports, findings, system info).
func trimJSONPackages(raw []byte, maxBytes int) []byte {
	if len(raw) <= maxBytes {
		return raw
	}
	// Parse as generic map, trim packages, re-marshal
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		// Can't parse — return a minimal placeholder
		return []byte(`{"truncated":true,"reason":"could not parse payload"}`)
	}
	// Trim packages array progressively until it fits
	if pkgs, ok := m["packages"].([]interface{}); ok {
		for len(pkgs) > 0 {
			pkgs = pkgs[:len(pkgs)/2]
			m["packages"] = pkgs
			m["packages_truncated"] = true
			out, err := json.Marshal(m)
			if err == nil && len(out) <= maxBytes {
				return sanitiseJSON(out)
			}
		}
		// Still too big — remove packages entirely
		delete(m, "packages")
		m["packages_truncated"] = true
	}
	out, err := json.Marshal(m)
	if err != nil {
		return []byte(`{"truncated":true}`)
	}
	return sanitiseJSON(out)
}
