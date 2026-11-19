package api

// hunt.go - threat hunting at scale.
//
//   - Live fleet query: ask every connected agent a fixed, read-only question
//     (processes, connections, persistence, software, users, file search) and
//     collect the answers per host.
//   - History hunt: run a KQL-style query over stored events and roll the hits
//     up per host, so "who else did this?" is one click.
//   - Library: curated hunts of each kind.

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

var liveHuntKinds = map[string]bool{"processes": true, "connections": true, "listening": true, "persistence": true, "software": true, "users": true, "file_find": true}

const (
	huntPerHostRows  = 500
	huntMaxAgents    = 500
	huntAgentTimeout = 120 * time.Second
)

// POST /api/v1/hunt/live
func handleStartFleetHunt(db *store.DB, reg *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name     string   `json:"name"`
			Kind     string   `json:"kind"`
			Match    string   `json:"match"`
			Path     string   `json:"path"`
			AgentIDs []string `json:"agent_ids"`
			OS       string   `json:"os"` // "", windows, linux, macos
			// Offline hosts: "skip" (default) asks only hosts connected now; "wait" stores the question for the
			// others and sends it when they reconnect, for up to WaitHours (default 24, max 168).
			Offline   string `json:"offline"`
			WaitHours int    `json:"wait_hours"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if !liveHuntKinds[req.Kind] {
			writeJSON(w, 400, map[string]string{"error": "unknown query kind"})
			return
		}
		req.Match = strings.TrimSpace(req.Match)
		if len(req.Match) > 500 || len(req.Path) > 2048 {
			writeJSON(w, 400, map[string]string{"error": "match or path too long"})
			return
		}
		if req.Kind == "file_find" {
			if req.Match == "" {
				writeJSON(w, 400, map[string]string{"error": "file search needs a file name or sha256:<hash>"})
				return
			}
			if req.Path != "" && !absPath(req.Path) {
				writeJSON(w, 400, map[string]string{"error": "path must be absolute"})
				return
			}
		}
		agents, err := db.ListAgents(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
		want := map[string]bool{}
		for _, id := range req.AgentIDs {
			want[id] = true
		}
		wait := req.Offline == "wait"
		var expires *time.Time
		if wait {
			if req.WaitHours <= 0 {
				req.WaitHours = 24
			}
			if req.WaitHours > 168 {
				req.WaitHours = 168
			}
			t := time.Now().Add(time.Duration(req.WaitHours) * time.Hour)
			expires = &t
		}
		osf := strings.ToLower(req.OS)
		var targets []store.Agent
		skipped := 0
		for _, a := range agents {
			if len(want) > 0 && !want[a.ID] {
				continue
			}
			if osf != "" && !strings.Contains(strings.ToLower(a.OS), osf) {
				continue
			}
			if _, up := reg.Get(a.ID); !up && len(want) == 0 && !wait {
				skipped++ // "whole fleet" only means agents we can reach right now
				continue
			}
			targets = append(targets, a)
		}
		if len(targets) == 0 {
			writeJSON(w, 409, map[string]string{"error": "no connected agents match; agents need live_response enabled and a connected tunnel"})
			return
		}
		if len(targets) > huntMaxAgents {
			targets = targets[:huntMaxAgents]
		}
		offline := map[string]bool{}
		if wait {
			for _, a := range targets {
				if _, up := reg.Get(a.ID); !up {
					offline[a.ID] = true
				}
			}
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = req.Kind
			if req.Match != "" {
				name += ": " + req.Match
			}
		}
		by := actor(r)
		h := store.FleetHunt{ID: newToken(), Name: name, Kind: req.Kind, Match: req.Match, Path: req.Path, RequestedBy: by}
		if err := db.CreateFleetHunt(r.Context(), h, targets, offline, expires); err != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
		db.WriteAudit(r.Context(), by, "fleet_hunt", "hunt:"+h.ID, fmt.Sprintf("kind=%s match=%q hosts=%d", req.Kind, req.Match, len(targets)), clientIP(r))
		logger.Info("fleet hunt started", "id", h.ID, "kind", req.Kind, "hosts", len(targets), "by", by)

		params := mustJSON(map[string]any{"kind": req.Kind, "match": req.Match, "path": req.Path, "limit": huntPerHostRows})
		for _, a := range targets {
			a := a
			t, up := reg.Get(a.ID)
			if offline[a.ID] {
				continue // stored as queued; sent by dispatchQueuedHunts when the agent reconnects
			}
			if !up {
				_ = db.CompleteHuntResult(r.Context(), h.ID, a.ID, "offline", "agent was offline; not asked", nil, nil, 0, false)
				continue
			}
			tok := newToken()
			reg.broker.expect(tok, huntAgentTimeout, func(res actionResult) { saveHuntResult(db, h.ID, a.ID, res) })
			if err := sendAction(t, tok, "query", params); err != nil {
				reg.broker.deliver(tok, mustJSON(actionResult{Message: "could not reach the agent: " + err.Error()}))
			}
		}
		writeJSON(w, 202, map[string]any{"id": h.ID, "agents": len(targets), "skipped_offline": skipped, "queued": len(offline)})
	}
}

// dispatchQueuedHunts sends the hunts that were waiting for this agent. Called when its tunnel connects.
func dispatchQueuedHunts(db *store.DB, reg *TunnelRegistry, agentID string, logger *slog.Logger) {
	time.Sleep(2 * time.Second) // let the agent finish its own startup before the first question
	ctx := contextBG()
	qs, err := db.ClaimQueuedHunts(ctx, agentID)
	if err != nil {
		logger.Warn("hunt: claim queued failed", "agent", agentID, "err", err)
		return
	}
	for _, q := range qs {
		q := q
		t, up := reg.Get(agentID)
		if !up {
			return
		}
		params := mustJSON(map[string]any{"kind": q.Kind, "match": q.Match, "path": q.Path, "limit": huntPerHostRows})
		tok := newToken()
		reg.broker.expect(tok, huntAgentTimeout, func(res actionResult) { saveHuntResult(db, q.ID, agentID, res) })
		if err := sendAction(t, tok, "query", params); err != nil {
			reg.broker.deliver(tok, mustJSON(actionResult{Message: "could not reach the agent: " + err.Error()}))
		}
		logger.Info("hunt: sent queued hunt to reconnected agent", "agent", agentID, "hunt", q.ID)
	}
}

func saveHuntResult(db *store.DB, huntID, agentID string, res actionResult) {
	status := "ok"
	if !res.OK {
		status = "failed"
		if strings.HasPrefix(res.Message, "timeout") {
			status = "timeout"
		}
	}
	var tb struct {
		Columns   json.RawMessage `json:"columns"`
		Rows      json.RawMessage `json:"rows"`
		Truncated bool            `json:"truncated"`
	}
	n := 0
	if res.OK && len(res.Data) > 0 {
		if json.Unmarshal(res.Data, &tb) == nil {
			var rows []json.RawMessage
			_ = json.Unmarshal(tb.Rows, &rows)
			n = len(rows)
		}
	}
	_ = db.CompleteHuntResult(contextBG(), huntID, agentID, status, res.Message, tb.Columns, tb.Rows, n, tb.Truncated)
}

// GET /api/v1/hunt/live
func handleListFleetHunts(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l, err := db.ListFleetHunts(r.Context(), 30)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, 200, map[string]any{"hunts": l})
	}
}

// GET /api/v1/hunt/live/{id}
func handleGetFleetHunt(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h, res, err := db.GetFleetHunt(r.Context(), r.PathValue("id"))
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "hunt not found"})
			return
		}
		writeJSON(w, 200, map[string]any{"hunt": h, "results": res})
	}
}

// GET /api/v1/hunt/live/{id}/csv
func handleFleetHuntCSV(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h, res, err := db.GetFleetHunt(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, "hunt not found", 404)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="hunt-`+h.ID+`.csv"`)
		cw := csv.NewWriter(w)
		defer cw.Flush()
		wrote := false
		for _, hr := range res {
			var cols []string
			var rows [][]string
			_ = json.Unmarshal(hr.Columns, &cols)
			_ = json.Unmarshal(hr.Rows, &rows)
			if len(cols) == 0 {
				continue
			}
			if !wrote {
				_ = cw.Write(append([]string{"host", "os"}, csvSafeRow(cols)...))
				wrote = true
			}
			for _, row := range rows {
				_ = cw.Write(append([]string{csvSafe(hr.Hostname), hr.OS}, csvSafeRow(row)...))
			}
		}
	}
}

func csvSafeRow(r []string) []string {
	o := make([]string, len(r))
	for i, v := range r {
		o[i] = csvSafe(v)
	}
	return o
}

// GET /api/v1/hunt/history?q=...&since=24h&limit=200
func handleHistoryHunt(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		raw := strings.TrimSpace(q.Get("q"))
		if raw == "" {
			writeJSON(w, 400, map[string]string{"error": "a query is required"})
			return
		}
		expr, perr := store.ParseEventQuery(raw)
		if perr != nil {
			writeJSON(w, 400, map[string]string{"error": perr.Error()})
			return
		}
		since := time.Now().Add(-24 * time.Hour)
		switch q.Get("since") {
		case "1h":
			since = time.Now().Add(-time.Hour)
		case "6h":
			since = time.Now().Add(-6 * time.Hour)
		case "7d":
			since = time.Now().Add(-7 * 24 * time.Hour)
		case "30d":
			since = time.Now().Add(-30 * 24 * time.Hour)
		case "90d":
			since = time.Now().Add(-90 * 24 * time.Hour)
		}
		f := store.EventFilter{Expr: expr, Since: since}
		ctx, cancel := contextWithTimeout(r, 20*time.Second)
		defer cancel()
		hosts, total, err := db.HuntRollup(ctx, f, 300)
		if err != nil {
			var qe *store.QueryError
			if errors.As(err, &qe) {
				writeJSON(w, 400, map[string]string{"error": qe.Error()})
				return
			}
			writeJSON(w, 500, map[string]string{"error": "hunt failed"})
			return
		}
		var events int64
		for _, h := range hosts {
			events += h.Count
		}
		writeJSON(w, 200, map[string]any{"query": raw, "since": since, "hosts": hosts, "total_hosts": total, "total_events": events})
	}
}

// ── library ──────────────────────────────────────────────────────────────────

type huntLib struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Desc   string `json:"desc"`
	Mode   string `json:"mode"` // history | live
	Query  string `json:"query,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Match  string `json:"match,omitempty"`
	Path   string `json:"path,omitempty"`
	Attack string `json:"attack,omitempty"`
}

var huntLibrary = []huntLib{
	{"h-encoded-ps", "Encoded PowerShell", "PowerShell started with an encoded or hidden command", "history", `type:process cmd:(-enc or -encodedcommand or "-e " or -w hidden or -windowstyle hidden)`, "", "", "", "T1059.001"},
	{"h-lolbin-dl", "LOLBin downloads", "certutil, bitsadmin, mshta, regsvr32 and curl/wget fetching remote content", "history", `type:process (cmd:(*urlcache* or *bitsadmin*/transfer* or *mshta*http* or *scrobj.dll* or *regsvr32*/i:http*) or (proc:(curl or wget) and cmd:http))`, "", "", "", "T1105"},
	{"h-office-spawn", "Office spawning a shell", "Word, Excel or Outlook launching cmd, PowerShell, wscript or mshta", "history", `type:process cmd:(*cmd.exe* or *powershell* or *wscript* or *cscript* or *mshta*) and image:(*winword* or *excel* or *outlook* or *powerpnt*)`, "", "", "", "T1204.002"},
	{"h-rmm-tools", "Remote access tools", "AnyDesk, TeamViewer, UltraViewer, ScreenConnect, RustDesk, Splashtop running", "history", `type:process proc:(anydesk or teamviewer or ultraviewer or screenconnect or rustdesk or splashtop or ammyy)`, "", "", "", "T1219"},
	{"h-shadow-delete", "Shadow copy / backup deletion", "vssadmin, wmic shadowcopy, bcdedit and wbadmin used to destroy recovery", "history", `type:process cmd:(*delete shadows* or *shadowcopy*delete* or *recoveryenabled*no* or *wbadmin*delete*)`, "", "", "", "T1490"},
	{"h-cred-dump", "Credential dumping", "lsass access, procdump, mimikatz strings, comsvcs MiniDump, ntds.dit", "history", `type:process cmd:(*lsass* or *mimikatz* or *sekurlsa* or *minidump* or *ntds.dit* or *procdump*)`, "", "", "", "T1003"},
	{"h-susp-ports", "Outbound to C2-style ports", "Connections to 4444, 1337, 31337, 9001 and IRC ports", "history", `type:network (dstport=4444 or dstport=1337 or dstport=31337 or dstport=9001 or dstport=6667)`, "", "", "", "T1571"},
	{"h-dns-tunnel", "Long DNS names", "DNS queries to unusually long names (possible tunnelling)", "history", `type:dns cmd:*`, "", "", "", "T1071.004"},
	{"h-new-service", "New services and tasks", "Service installs and scheduled task creation", "history", `type:process cmd:(*sc create* or *schtasks*/create* or *New-Service* or *systemctl enable*)`, "", "", "", "T1543"},
	{"h-persist-startup", "Startup-folder / Run-key writes", "Files written to Startup and Run key changes", "history", `(type:file path:(*\\start menu\\programs\\startup* or */etc/cron* or */etc/systemd/system*)) or (type:registry reg:(*\\currentversion\\run*))`, "", "", "", "T1547"},
	{"h-ssh-keys", "SSH key changes", "authorized_keys modified", "history", `type:file path:*authorized_keys*`, "", "", "", "T1098.004"},
	{"h-log-clear", "Log clearing", "wevtutil cl, Clear-EventLog, history -c, log truncation", "history", `type:process cmd:(*wevtutil*cl* or *clear-eventlog* or *history -c* or *truncate*/var/log*)`, "", "", "", "T1070"},
	{"h-archive-exfil", "Archiving and exfil tools", "rclone, megacmd, 7z/rar with passwords, pscp, winscp", "history", `type:process proc:(rclone or megacmd or pscp or winscp) or cmd:(*7z*-p* or *rar*-hp*)`, "", "", "", "T1560"},
	{"l-listen", "Listening ports (live)", "Every listening port on every connected host", "live", "", "listening", "", "", ""},
	{"l-persistence", "Persistence items (live)", "Run keys, scheduled tasks, services, cron, systemd, launch agents, SSH keys", "live", "", "persistence", "", "", "T1547"},
	{"l-admins", "Local administrators (live)", "Accounts with admin rights per host", "live", "", "users", "admin:yes", "", "T1078"},
	{"l-rmm", "Remote access tools installed (live)", "Installed software matching common RMM tools", "live", "", "software", "anydesk teamviewer ultraviewer screenconnect rustdesk splashtop", "", "T1219"},
	{"l-tmp-proc", "Processes running from temp/user dirs (live)", "Running binaries launched from Temp, Downloads, AppData or /tmp", "live", "", "processes", "path:\\temp\\", "", "T1036"},
}

func handleHuntLibrary() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"hunts": huntLibrary, "kinds": []string{"processes", "connections", "listening", "persistence", "software", "users", "file_find"}})
	}
}

func contextBG() context.Context { return context.Background() }

func contextWithTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
