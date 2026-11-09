package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Event struct {
	ID          string          `json:"id"`
	Time        time.Time       `json:"time"`
	IngestedAt  time.Time       `json:"ingested_at,omitempty"`
	AgentID     string          `json:"agent_id"`
	Host        string          `json:"host"`
	OS          string          `json:"os"`
	EventType   string          `json:"event_type"`
	Severity    int             `json:"severity"`
	Source      string          `json:"source"`
	Raw         json.RawMessage `json:"raw,omitempty"`
	PID         *int            `json:"pid,omitempty"`
	PPID        *int            `json:"ppid,omitempty"`
	ProcessName *string         `json:"process_name,omitempty"`
	CommandLine *string         `json:"command_line,omitempty"`
	ImagePath   *string         `json:"image_path,omitempty"`
	UserName    *string         `json:"user_name,omitempty"`
	Domain      *string         `json:"domain,omitempty"`
	LogonID     *string         `json:"logon_id,omitempty"`
	SrcIP       *string         `json:"src_ip,omitempty"`
	SrcPort     *int            `json:"src_port,omitempty"`
	DstIP       *string         `json:"dst_ip,omitempty"`
	DstPort     *int            `json:"dst_port,omitempty"`
	Proto       *string         `json:"proto,omitempty"`
	RegKey      *string         `json:"reg_key,omitempty"`
	RegValue    *string         `json:"reg_value,omitempty"`
	RegData     *string         `json:"reg_data,omitempty"`
	FilePath    *string         `json:"file_path,omitempty"`
	FileHash    *string         `json:"file_hash,omitempty"`
	EventID     *uint32         `json:"event_id,omitempty"`
	Channel     *string         `json:"channel,omitempty"`
	RecordID    *uint64         `json:"record_id,omitempty"`
}

// EventFilter is the full set of supported search parameters.
type EventFilter struct {
	AgentID string
	// Host does a substring match (ILIKE %host%) — intended for the
	// free-text event search UI, where "web" is meant to also surface
	// "web-prod" and "webdev". F-10: several host-*scoped* endpoints
	// (threat graph, per-host vuln lookup, per-host RCA/alerts) used to
	// reuse this same substring filter, which meant looking up "web"
	// silently pulled in events from unrelated hosts like "web-prod" and
	// "webdev" too. Those call sites should set HostExact instead.
	Host string
	// HostExact does an exact match (host = $n) and takes priority over
	// Host when both are set. Use this for anything scoped to one
	// specific, already-known host/agent.
	HostExact   string
	OS          string
	EventType   string
	Severity    int
	SrcIP       string
	DstIP       string
	SrcOrDstIP  string // matches either src_ip or dst_ip
	DstPort     int
	SrcPort     int
	Proto       string
	UserName    string
	ProcessName string
	CommandLine string
	ImagePath   string
	FilePath    string
	RegKey      string
	Channel     string
	EventID     uint32
	Source      string   // filter by source (e.g. "cloudtrail", "guardduty")
	Search      string   // free-text across key fields
	Tokens      []string // multi-token search — all tokens must match (AND logic)
	NotTokens   []string // F-07: events matching any of these tokens are excluded
	Since       time.Time
	Until       time.Time
	// IngestedAfter (D-01/D-02): when set, filters and orders by
	// ingested_at instead of time, and takes priority over Since/Until.
	// This is what cursor-based engine polling uses (see
	// cursor_paging.go) so that an event whose agent reported an old
	// `time` because it queued/retried delivery still gets picked up by
	// the very next poll, instead of potentially never falling inside
	// any future wall-clock window again.
	IngestedAfter time.Time
	// SkipCount (D-08): COUNT(*) over the whole table is wasted work for
	// an engine that only wants the rows, not a total — skip it.
	SkipCount bool
	// SkipEnrich (D-08): enrichFromRaw does a full JSON unmarshal of the
	// raw event blob on every single row, to backfill structured columns
	// left NULL by events ingested before the normalizer populated them.
	// New events already have those columns populated at ingest time, so
	// for an engine re-running this on every tick it's wasted CPU on
	// almost every row. Callers that read structured fields directly off
	// freshly-ingested events (the detection/alert/correlation engines)
	// should set this; anything that might show raw/legacy events to a
	// person (search, exports) should leave it false.
	SkipEnrich bool
	Limit      int
	Offset     int
}

func (db *DB) QueryEvents(ctx context.Context, f EventFilter) ([]Event, int64, error) {
	where, args, n := []string{"1=1"}, []interface{}{}, 1

	if f.AgentID != "" {
		where = append(where, fmt.Sprintf("agent_id = $%d", n))
		args = append(args, f.AgentID)
		n++
	}
	if f.HostExact != "" {
		where = append(where, fmt.Sprintf("host = $%d", n))
		args = append(args, f.HostExact)
		n++
	} else if f.Host != "" {
		where = append(where, fmt.Sprintf("host ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.Host)+"%")
		n++
	}
	if f.OS != "" {
		where = append(where, fmt.Sprintf("os ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.OS)+"%")
		n++
	}
	if f.EventType != "" {
		if strings.HasSuffix(f.EventType, "*") {
			// Prefix match — e.g. "cloud.*" matches all cloud events
			prefix := strings.TrimSuffix(f.EventType, "*")
			where = append(where, fmt.Sprintf("event_type LIKE $%d", n))
			args = append(args, prefix+"%")
		} else {
			where = append(where, fmt.Sprintf("event_type = $%d", n))
			args = append(args, f.EventType)
		}
		n++
	}
	if f.Severity > 0 {
		where = append(where, fmt.Sprintf("severity >= $%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.SrcIP != "" {
		where = append(where, fmt.Sprintf("src_ip = $%d", n))
		args = append(args, f.SrcIP)
		n++
	}
	if f.DstIP != "" {
		where = append(where, fmt.Sprintf("dst_ip = $%d", n))
		args = append(args, f.DstIP)
		n++
	}
	if f.SrcOrDstIP != "" {
		where = append(where, fmt.Sprintf("(src_ip = $%d OR dst_ip = $%d)", n, n+1))
		args = append(args, f.SrcOrDstIP, f.SrcOrDstIP)
		n += 2
	}
	if f.DstPort > 0 {
		where = append(where, fmt.Sprintf("dst_port = $%d", n))
		args = append(args, f.DstPort)
		n++
	}
	if f.SrcPort > 0 {
		where = append(where, fmt.Sprintf("src_port = $%d", n))
		args = append(args, f.SrcPort)
		n++
	}
	if f.Proto != "" {
		where = append(where, fmt.Sprintf("proto ILIKE $%d", n))
		args = append(args, f.Proto)
		n++
	}
	if f.UserName != "" {
		where = append(where, fmt.Sprintf("user_name ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.UserName)+"%")
		n++
	}
	if f.ProcessName != "" {
		where = append(where, fmt.Sprintf("process_name ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.ProcessName)+"%")
		n++
	}
	if f.CommandLine != "" {
		where = append(where, fmt.Sprintf("command_line ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.CommandLine)+"%")
		n++
	}
	if f.ImagePath != "" {
		where = append(where, fmt.Sprintf("image_path ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.ImagePath)+"%")
		n++
	}
	if f.FilePath != "" {
		where = append(where, fmt.Sprintf("file_path ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.FilePath)+"%")
		n++
	}
	if f.RegKey != "" {
		where = append(where, fmt.Sprintf("reg_key ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.RegKey)+"%")
		n++
	}
	if f.Channel != "" {
		where = append(where, fmt.Sprintf("channel ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.Channel)+"%")
		n++
	}
	if f.EventID > 0 {
		where = append(where, fmt.Sprintf("event_id = $%d", n))
		args = append(args, f.EventID)
		n++
	}
	if f.Source != "" {
		where = append(where, fmt.Sprintf("source ILIKE $%d", n))
		args = append(args, "%"+escapeLike(f.Source)+"%")
		n++
	}
	if f.Search != "" {
		v := "%" + escapeLike(f.Search) + "%"
		clause := fmt.Sprintf(`(
			host ILIKE $%d OR user_name ILIKE $%d OR process_name ILIKE $%d
			OR command_line ILIKE $%d OR src_ip = $%d OR dst_ip = $%d
			OR image_path ILIKE $%d OR file_path ILIKE $%d OR reg_key ILIKE $%d
			OR reg_value ILIKE $%d OR raw::text ILIKE $%d
		)`, n, n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9, n+10)
		where = append(where, clause)
		args = append(args, v, v, v, v, f.Search, f.Search, v, v, v, v, v)
		n += 11
	}
	if len(f.Tokens) > 0 {
		// Multi-token AND search — each token must match at least one field or raw JSON
		for _, tok := range f.Tokens {
			v := "%" + tok + "%"
			clause := fmt.Sprintf(`(
				host ILIKE $%d OR user_name ILIKE $%d OR process_name ILIKE $%d
				OR command_line ILIKE $%d OR src_ip ILIKE $%d OR dst_ip ILIKE $%d
				OR image_path ILIKE $%d OR file_path ILIKE $%d OR event_type ILIKE $%d
				OR source ILIKE $%d OR os ILIKE $%d OR raw::text ILIKE $%d
			)`, n, n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9, n+10, n+11)
			where = append(where, clause)
			args = append(args, v, v, v, v, v, v, v, v, v, v, v, v)
			n += 12
		}
	}
	for _, tok := range f.NotTokens {
		v := "%" + escapeLike(tok) + "%"
		where = append(where, fmt.Sprintf(`NOT (
			COALESCE(host,'') ILIKE $%d OR COALESCE(user_name,'') ILIKE $%d OR COALESCE(process_name,'') ILIKE $%d
			OR COALESCE(command_line,'') ILIKE $%d OR COALESCE(image_path,'') ILIKE $%d
			OR COALESCE(file_path,'') ILIKE $%d OR raw::text ILIKE $%d)`, n, n+1, n+2, n+3, n+4, n+5, n+6))
		args = append(args, v, v, v, v, v, v, v)
		n += 7
	}
	if !f.IngestedAfter.IsZero() {
		where = append(where, fmt.Sprintf("ingested_at > $%d", n))
		args = append(args, f.IngestedAfter.UTC())
		n++
	} else {
		if !f.Since.IsZero() {
			where = append(where, fmt.Sprintf("time >= $%d", n))
			args = append(args, f.Since.UTC())
			n++
		}
		if !f.Until.IsZero() {
			where = append(where, fmt.Sprintf("time <= $%d", n))
			args = append(args, f.Until.UTC())
			n++
		}
	}

	if f.Limit <= 0 {
		f.Limit = 100
	} else if f.Limit > 5000 {
		f.Limit = 5000
	}

	whereStr := strings.Join(where, " AND ")

	var total int64
	if !f.SkipCount {
		db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s`, whereStr), args...).Scan(&total)
	}

	orderBy := "time DESC"
	if !f.IngestedAfter.IsZero() {
		// Cursor mode: ascending ingested_at so the caller can advance its
		// cursor to the last row returned and never re-read or skip a row.
		orderBy = "ingested_at ASC"
	}
	query := fmt.Sprintf(`
		SELECT id, time, ingested_at, agent_id, host, os, event_type, severity, source, raw,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, reg_data, file_path, file_hash,
		       event_id, channel, record_id
		FROM events WHERE %s
		ORDER BY %s
		LIMIT %d OFFSET %d`, whereStr, orderBy, f.Limit, f.Offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: query events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var rawBytes []byte
		if err := rows.Scan(
			&e.ID, &e.Time, &e.IngestedAt, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source, &rawBytes,
			&e.PID, &e.PPID, &e.ProcessName, &e.CommandLine, &e.ImagePath, &e.UserName, &e.Domain, &e.LogonID,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto,
			&e.RegKey, &e.RegValue, &e.RegData, &e.FilePath, &e.FileHash,
			&e.EventID, &e.Channel, &e.RecordID,
		); err != nil {
			return nil, 0, err
		}
		if rawBytes != nil {
			e.Raw = json.RawMessage(rawBytes)
			if !f.SkipEnrich {
				enrichFromRaw(&e)
			}
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

func (db *DB) LatestEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source, raw,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, reg_data, file_path, file_hash,
		       event_id, channel, record_id
		FROM events WHERE time > $1 ORDER BY time DESC LIMIT $2
	`, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (db *DB) GetEventByID(ctx context.Context, id string) (*Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source, raw,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, reg_data, file_path, file_hash,
		       event_id, channel, record_id
		FROM events WHERE id = $1
	`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source, &e.Raw,
			&e.PID, &e.PPID, &e.ProcessName, &e.CommandLine, &e.ImagePath, &e.UserName, &e.Domain, &e.LogonID,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto,
			&e.RegKey, &e.RegValue, &e.RegData, &e.FilePath, &e.FileHash,
			&e.EventID, &e.Channel, &e.RecordID,
		); err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, fmt.Errorf("event not found")
}

func (db *DB) RelatedEvents(ctx context.Context, host string, t time.Time, excludeID string) ([]Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source, raw,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, reg_data, file_path, file_hash,
		       event_id, channel, record_id
		FROM events
		WHERE host = $1 AND time BETWEEN $2 AND $3 AND id != $4
		ORDER BY time DESC LIMIT 50
	`, host, t.Add(-5*time.Minute).UTC(), t.Add(5*time.Minute).UTC(), excludeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (db *DB) ExportEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	if f.Limit <= 0 || f.Limit > 10000 {
		f.Limit = 10000
	}
	events, _, err := db.QueryEvents(ctx, f)
	return events, err
}

func scanEvents(rows interface {
	Next() bool
	Scan(...interface{}) error
	Err() error
}) ([]Event, error) {
	var events []Event
	for rows.Next() {
		var e Event
		var rawBytes []byte
		if err := rows.Scan(
			&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source, &rawBytes,
			&e.PID, &e.PPID, &e.ProcessName, &e.CommandLine, &e.ImagePath, &e.UserName, &e.Domain, &e.LogonID,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto,
			&e.RegKey, &e.RegValue, &e.RegData, &e.FilePath, &e.FileHash,
			&e.EventID, &e.Channel, &e.RecordID,
		); err != nil {
			return nil, err
		}
		if rawBytes != nil {
			e.Raw = json.RawMessage(rawBytes)
			enrichFromRaw(&e)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// enrichFromRaw extracts structured fields from the raw JSON blob when the
// structured columns are NULL. This handles events ingested before the
// normalizer was fully tuned, or events where Windows event_data keys differ.
func enrichFromRaw(e *Event) {
	if e.Raw == nil {
		return
	}
	var r struct {
		Image          string            `json:"Image"`
		CommandLine    string            `json:"CommandLine"`
		CommandLineLow string            `json:"command_line"` // WMI fallback uses lowercase
		ProcessNameLow string            `json:"process_name"` // WMI fallback
		User           string            `json:"User"`
		UserLow        string            `json:"user_name"` // WMI/Linux
		ProcessID      int               `json:"ProcessId"`
		TargetFilename string            `json:"TargetFilename"`
		QueryName      string            `json:"query_name"`
		DestIP         string            `json:"DestinationIp"`
		DestPort       int               `json:"DestinationPort"`
		SrcIP          string            `json:"SourceIp"`
		SrcPort        int               `json:"SourcePort"`
		Protocol       string            `json:"Protocol"`
		TargetObject   string            `json:"TargetObject"`
		Details        string            `json:"Details"`
		FilePath       string            `json:"file_path"` // Linux/macOS
		FileHash       string            `json:"file_hash"` // Linux/macOS
		DstIP          string            `json:"dst_ip"`    // Linux/macOS network
		DstPort        int               `json:"dst_port"`  // Linux/macOS network
		SrcIPLow       string            `json:"src_ip"`    // Linux/macOS network
		SrcPortLow     int               `json:"src_port"`  // Linux/macOS network
		ProtoLow       string            `json:"proto"`     // Linux/macOS network
		EventData      map[string]string `json:"event_data"`
	}
	if err := json.Unmarshal(e.Raw, &r); err != nil {
		return
	}

	setStr := func(field **string, val string) {
		if *field == nil && val != "" {
			v := val
			*field = &v
		}
	}
	setPtrInt := func(field **int, val int) {
		if *field == nil && val != 0 {
			v := val
			*field = &v
		}
	}

	setStr(&e.ProcessName, lastName(r.Image))
	setStr(&e.ProcessName, r.ProcessNameLow) // WMI lowercase
	setStr(&e.ImagePath, r.Image)
	setStr(&e.CommandLine, r.CommandLine)
	setStr(&e.CommandLine, r.CommandLineLow) // WMI lowercase
	setStr(&e.UserName, lastName(r.User))
	setStr(&e.UserName, r.UserLow) // WMI/Linux lowercase
	setStr(&e.FilePath, r.TargetFilename)
	setStr(&e.FilePath, r.FilePath) // Linux/macOS
	setStr(&e.FileHash, r.FileHash) // Linux/macOS
	setStr(&e.DstIP, r.QueryName)
	setStr(&e.DstIP, r.DestIP)
	setStr(&e.DstIP, r.DstIP) // Linux/macOS
	setStr(&e.SrcIP, r.SrcIP)
	setStr(&e.SrcIP, r.SrcIPLow) // Linux/macOS
	setStr(&e.Proto, r.Protocol)
	setStr(&e.Proto, r.ProtoLow) // Linux/macOS
	setPtrInt(&e.PID, r.ProcessID)
	setPtrInt(&e.DstPort, r.DestPort)
	setPtrInt(&e.DstPort, r.DstPort) // Linux/macOS
	setPtrInt(&e.SrcPort, r.SrcPort)
	setPtrInt(&e.SrcPort, r.SrcPortLow) // Linux/macOS
	setStr(&e.RegKey, r.TargetObject)
	setStr(&e.RegValue, r.Details)

	if d := r.EventData; d != nil {
		// "Image" is the Sysmon key for the full executable path
		setStr(&e.ProcessName, lastName(firstOfMap(d, "Image", "NewProcessName", "ProcessName", "Application", "ParentImage")))
		setStr(&e.ImagePath, firstOfMap(d, "Image", "NewProcessName", "ProcessName", "Application"))
		setStr(&e.CommandLine, firstOfMap(d, "CommandLine"))
		setStr(&e.UserName, firstOfMap(d, "User", "SubjectUserName", "TargetUserName", "UserName"))
		setStr(&e.Domain, firstOfMap(d, "SubjectDomainName", "TargetDomainName", "Domain"))
		setStr(&e.FilePath, firstOfMap(d, "TargetFilename", "ObjectName", "FileName", "FilePath"))
		setStr(&e.RegKey, firstOfMap(d, "TargetObject", "ObjectName", "KeyPath"))
		setStr(&e.RegValue, firstOfMap(d, "Details", "NewValue", "OldValue", "ValueName"))
		setStr(&e.SrcIP, firstOfMap(d, "SourceIp", "IpAddress", "SourceAddress", "WorkstationName"))
		setStr(&e.DstIP, firstOfMap(d, "DestinationIp", "DestAddress", "TargetServerName", "QueryName"))
		setStr(&e.LogonID, firstOfMap(d, "SubjectLogonId", "TargetLogonId"))
		if v := firstOfMap(d, "SourcePort"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				setPtrInt(&e.SrcPort, p)
			}
		}
		if v := firstOfMap(d, "DestPort"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				setPtrInt(&e.DstPort, p)
			}
		}
		if v := firstOfMap(d, "NewProcessId", "ProcessId", "ProcessID"); v != "" {
			v = strings.TrimPrefix(v, "0x")
			if pid, err := strconv.ParseInt(v, 16, 64); err == nil {
				setPtrInt(&e.PID, int(pid))
			} else if pid, err := strconv.Atoi(v); err == nil {
				setPtrInt(&e.PID, pid)
			}
		}
	}
}

func lastName(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "\\")
	return parts[len(parts)-1]
}

func firstOfMap(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" {
			return v
		}
	}
	return ""
}

// escapeLike escapes LIKE/ILIKE metacharacters so user input is matched
// literally (F-07): "%" and "_" in a search term no longer act as wildcards.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
