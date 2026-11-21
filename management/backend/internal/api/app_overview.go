package api

// app_overview.go - Overview aggregate, per-service alerts and app.security events.
// Owned by the Application build.
//
//	GET /api/v1/app/overview               posture + what changed in the range
//	GET /api/v1/app/services/{id}/alerts   alerts linked to the service entity (state=open|all)
//	GET /api/v1/app/services/{id}/events   app.security events for the service

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"obsidianwatch/management/internal/store"
)

type appOverviewService struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Environment string `json:"environment"`
	Key         string `json:"key"`
}

func appHandleOverview(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		from, to, msg := appParseRange(r)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		ctx := r.Context()
		active := time.Now().UTC().Add(-24 * time.Hour) // "currently reporting" window for coverage

		// Services seen in the range, with the facts coverage needs.
		type svc struct {
			appOverviewService
			Source   string
			Attrs    map[string]any
			Asserted int
			Live     int
		}
		rows, err := idb.QueryContext(ctx, `
			SELECT s.id, s.name, s.environment, s.source, s.attrs,
			  (SELECT COUNT(*) FROM service_instances i WHERE i.service_id=s.id AND i.stopped_at IS NULL AND i.last_seen >= $2 AND i.identity='asserted'),
			  (SELECT COUNT(*) FROM service_instances i WHERE i.service_id=s.id AND i.stopped_at IS NULL AND i.last_seen >= $2)
			FROM services s WHERE s.last_seen >= $1 ORDER BY s.name LIMIT 2000`, from, active)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		var svcs []svc
		var ids []int64
		for rows.Next() {
			var s svc
			var attrs []byte
			if err := rows.Scan(&s.ID, &s.Name, &s.Environment, &s.Source, &attrs, &s.Asserted, &s.Live); err != nil {
				rows.Close()
				appQueryFailed(w, r.URL.Path, 0, err)
				return
			}
			s.Key = appServiceKey(s.Name, s.Environment)
			_ = json.Unmarshal(attrs, &s.Attrs)
			ids = append(ids, s.ID)
			svcs = append(svcs, s)
		}
		rows.Close()
		settings := appSettingsByID(ctx, db, ids)
		appApplyExposure(ctx, idb, ids, settings)

		exposure := map[string]int{"internet": 0, "internal": 0, "unknown": 0}
		criticality := map[string]int{"low": 0, "normal": 0, "high": 0, "critical": 0}
		tiers := map[string]int{"0": 0, "1": 0, "2": 0}
		var degraded []map[string]any
		keyToSvc := map[string]appOverviewService{}
		for _, s := range svcs {
			st, ok := settings[s.ID]
			if !ok {
				st = appDefaultSettings()
			}
			exposure[st.EffectiveExposure()]++
			criticality[st.Criticality]++
			tiers[strconv.Itoa(appTier(s.Source))]++
			keyToSvc[s.Key] = s.appOverviewService
			var reasons []string
			if s.Asserted > 0 {
				reasons = append(reasons, "asserted_identity")
			}
			if n, _ := s.Attrs["route_overflow"].(float64); n > 0 {
				reasons = append(reasons, "route_overflow")
			}
			if n, _ := s.Attrs["trace_drops"].(float64); n > 0 {
				reasons = append(reasons, "trace_drops")
			}
			if s.Source == "otel" && s.Live == 0 {
				reasons = append(reasons, "not_reporting")
			}
			if len(reasons) > 0 {
				degraded = append(degraded, map[string]any{"service": s.appOverviewService, "reasons": reasons})
			}
		}
		withOTel := tiers["1"] + tiers["2"]
		coverage := 0.0
		if len(svcs) > 0 {
			coverage = float64(withOTel) / float64(len(svcs))
		}

		// Open alerts by service (management tables).
		type alertAgg struct {
			Service     appOverviewService `json:"service"`
			Open        int                `json:"open"`
			MaxSeverity int                `json:"max_severity"`
		}
		openAlerts := []alertAgg{}
		totalOpen := 0
		if arows, err := db.QueryContext(ctx, `
			SELECT e.key, COUNT(*), COALESCE(MAX(a.severity),1)
			FROM alert_entities e JOIN alerts a ON a.id = e.alert_id
			WHERE e.kind = 'service' AND a.status <> 'closed'
			GROUP BY e.key ORDER BY COUNT(*) DESC LIMIT 20`); err == nil {
			for arows.Next() {
				var k string
				var ag alertAgg
				if arows.Scan(&k, &ag.Open, &ag.MaxSeverity) == nil {
					if sv, ok := keyToSvc[k]; ok {
						ag.Service = sv
					} else {
						n, e, _ := strings.Cut(k, "|")
						ag.Service = appOverviewService{Name: n, Environment: e, Key: k}
					}
					totalOpen += ag.Open
					openAlerts = append(openAlerts, ag)
				}
			}
			arows.Close()
		}

		// What changed in the range.
		newServices := []appOverviewService{}
		if r2, err := idb.QueryContext(ctx, `SELECT id, name, environment FROM services WHERE first_seen >= $1 ORDER BY first_seen DESC LIMIT 20`, from); err == nil {
			for r2.Next() {
				var s appOverviewService
				if r2.Scan(&s.ID, &s.Name, &s.Environment) == nil {
					s.Key = appServiceKey(s.Name, s.Environment)
					newServices = append(newServices, s)
				}
			}
			r2.Close()
		}
		type newEdge struct {
			Service   appOverviewService `json:"service"`
			DstKind   string             `json:"dst_kind"`
			DstName   string             `json:"dst_name"`
			FirstSeen time.Time          `json:"first_seen"`
		}
		newEdges := []newEdge{}
		if r3, err := idb.QueryContext(ctx, `
			SELECT s.id, s.name, s.environment, e.dst_kind, e.dst_name, e.first_seen
			FROM service_edges e JOIN services s ON s.id = e.src_service
			WHERE e.first_seen >= $1 AND e.first_seen > s.first_seen + interval '1 hour'
			ORDER BY e.first_seen DESC LIMIT 20`, from); err == nil { // an edge on day one is baseline, not a change
			for r3.Next() {
				var n newEdge
				if r3.Scan(&n.Service.ID, &n.Service.Name, &n.Service.Environment, &n.DstKind, &n.DstName, &n.FirstSeen) == nil {
					n.Service.Key = appServiceKey(n.Service.Name, n.Service.Environment)
					newEdges = append(newEdges, n)
				}
			}
			r3.Close()
		}
		var newRoutes int
		_ = idb.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_routes r JOIN services s ON s.id = r.service_id
			WHERE r.first_seen >= $1 AND r.first_seen > s.first_seen + interval '1 hour'`, from).Scan(&newRoutes)
		type deploy struct {
			Service   appOverviewService `json:"service"`
			Version   string             `json:"version"`
			FirstSeen time.Time          `json:"first_seen"`
		}
		deploys := []deploy{}
		if r4, err := idb.QueryContext(ctx, `
			SELECT s.id, s.name, s.environment, v.version, v.first_seen
			FROM service_versions v JOIN services s ON s.id = v.service_id
			WHERE v.first_seen >= $1 AND v.first_seen > s.first_seen + interval '1 hour'
			ORDER BY v.first_seen DESC LIMIT 20`, from); err == nil {
			for r4.Next() {
				var d deploy
				if r4.Scan(&d.Service.ID, &d.Service.Name, &d.Service.Environment, &d.Version, &d.FirstSeen) == nil {
					d.Service.Key = appServiceKey(d.Service.Name, d.Service.Environment)
					deploys = append(deploys, d)
				}
			}
			r4.Close()
		}
		if degraded == nil {
			degraded = []map[string]any{}
		}
		// Host sensor tier per host (spec 11.3 Coverage): ebpf | procevent | poll | unknown.
		sensors := map[string]int{"ebpf": 0, "procevent": 0, "poll": 0, "unknown": 0}
		pollHosts := []string{}
		if srows, err := idb.QueryContext(ctx, `
			SELECT COALESCE(NULLIF(attrs->>'sensor',''),'unknown') AS tier, host FROM service_instances
			WHERE stopped_at IS NULL AND last_seen >= $1 GROUP BY 1, 2 ORDER BY 2`, active); err == nil {
			for srows.Next() {
				var tier, host string
				if srows.Scan(&tier, &host) == nil {
					if _, ok := sensors[tier]; !ok {
						tier = "unknown"
					}
					sensors[tier]++
					if tier == "poll" && len(pollHosts) < 20 {
						pollHosts = append(pollHosts, host)
					}
				}
			}
			srows.Close()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"from": from, "to": to, "services": len(svcs),
			"exposure": exposure, "criticality": criticality, "tiers": tiers, "coverage": coverage,
			"open_alerts": openAlerts, "open_alerts_total": totalOpen,
			"changes":  map[string]any{"new_services": newServices, "new_dependencies": newEdges, "new_routes": newRoutes, "deploys": deploys},
			"degraded": degraded, "sensors": sensors, "poll_hosts": pollHosts,
		})
	}
}

func appHandleServiceAlerts(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var name, env string
		if err := idb.QueryRowContext(r.Context(), `SELECT name, environment FROM services WHERE id=$1`, id).Scan(&name, &env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		openOnly := r.URL.Query().Get("state") != "all"
		rows, err := db.QueryContext(r.Context(), `
			SELECT a.id, a.created_at, a.title, a.severity, a.status, COALESCE(a.host,''), COALESCE(a.event_type,'')
			FROM alerts a JOIN alert_entities e ON e.alert_id = a.id
			WHERE e.kind = 'service' AND e.key = $1 AND ($2 = false OR a.status <> 'closed')
			ORDER BY a.id DESC LIMIT $3`, appServiceKey(name, env), openOnly, limit)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		defer rows.Close()
		type al struct {
			ID        int64     `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			Title     string    `json:"title"`
			Severity  int       `json:"severity"`
			Status    string    `json:"status"`
			Host      string    `json:"host"`
			EventType string    `json:"event_type"`
		}
		list := []al{}
		for rows.Next() {
			var a al
			if rows.Scan(&a.ID, &a.CreatedAt, &a.Title, &a.Severity, &a.Status, &a.Host, &a.EventType) == nil {
				list = append(list, a)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"alerts": list})
	}
}

func appHandleServiceEvents(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		from, to, msg := appParseRange(r)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		var name, env string
		if err := idb.QueryRowContext(r.Context(), `SELECT name, environment FROM services WHERE id=$1`, id).Scan(&name, &env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		evName := strings.TrimSpace(r.URL.Query().Get("event_name"))
		rows, err := idb.QueryContext(r.Context(), `
			SELECT id, time, host, COALESCE(user_name,''), raw->'app'
			FROM events
			WHERE event_type = 'app.security' AND time >= $1 AND time < $2
			  AND raw->'app'->>'service' = $3 AND raw->'app'->>'environment' = $4
			  AND ($5 = '' OR raw->'app'->>'event.name' = $5)
			ORDER BY time DESC LIMIT $6`, from, to, name, env, evName, limit)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		defer rows.Close()
		type ev struct {
			ID       string          `json:"id"`
			Time     time.Time       `json:"time"`
			Host     string          `json:"host"`
			UserHash string          `json:"user"`
			App      json.RawMessage `json:"app"`
		}
		list := []ev{}
		for rows.Next() {
			var e ev
			var app []byte
			if rows.Scan(&e.ID, &e.Time, &e.Host, &e.UserHash, &app) == nil {
				e.App = json.RawMessage(app)
				list = append(list, e)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": list, "from": from, "to": to})
	}
}

// appHandleGetInstance resolves a service_instance entity key (its id) to the instance
// and its service, so entity chips can link to the right page.
func appHandleGetInstance(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var out struct {
			ID          int64      `json:"id"`
			ServiceID   int64      `json:"service_id"`
			Service     string     `json:"service"`
			Environment string     `json:"environment"`
			Key         string     `json:"key"`
			AgentID     string     `json:"agent_id"`
			Host        string     `json:"host"`
			PID         int        `json:"pid"`
			ContainerID string     `json:"container_id"`
			Version     string     `json:"version"`
			Identity    string     `json:"identity"`
			LastSeen    time.Time  `json:"last_seen"`
			StoppedAt   *time.Time `json:"stopped_at"`
		}
		var stopped sql.NullTime
		err = idb.QueryRowContext(r.Context(), `
			SELECT i.id, i.service_id, s.name, s.environment, i.agent_id, i.host, i.pid, i.container_id, i.version, i.identity, i.last_seen, i.stopped_at
			FROM service_instances i JOIN services s ON s.id = i.service_id WHERE i.id = $1`, id).
			Scan(&out.ID, &out.ServiceID, &out.Service, &out.Environment, &out.AgentID, &out.Host, &out.PID,
				&out.ContainerID, &out.Version, &out.Identity, &out.LastSeen, &stopped)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance not found"})
			return
		}
		if stopped.Valid {
			out.StoppedAt = &stopped.Time
		}
		out.Key = appServiceKey(out.Service, out.Environment)
		writeJSON(w, http.StatusOK, out)
	}
}

// appHandleServiceRuntime is the Runtime tab: what the host sensor saw under the service's processes.
//
//	GET /api/v1/app/services/{id}/runtime?from=&to=&type=process|network|file&limit=
//
// It returns the service's host instances (pid, container, listening ports, the sensor tier of the host)
// and the recent host events whose process is one of those instances or descends from one (raw.proc.ancestors).
// appQueryFailed logs the real database error (it used to be swallowed, which hid a bad query for weeks)
// and gives the UI something an operator can act on.
func appQueryFailed(w http.ResponseWriter, what string, serviceID int64, err error) {
	slog.Error("application monitoring query failed", "query", what, "service_id", serviceID, "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"error": "Could not read " + what + " for this service (database error). The details are in the management backend log under \"application monitoring query failed\".",
	})
}

func appHandleServiceRuntime(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		from, to, msg := appParseRange(r)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		typ := r.URL.Query().Get("type")
		if typ != "" && typ != "process" && typ != "network" && typ != "file" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be process, network or file"})
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 200
		}
		ctx := r.Context()
		irows, err := idb.QueryContext(ctx, `
			SELECT id, agent_id, host, pid, container_id, listen, instrumented, identity, COALESCE(NULLIF(i.attrs->>'sensor',''), (SELECT x.attrs->>'sensor' FROM service_instances x WHERE x.agent_id = i.agent_id AND COALESCE(x.attrs->>'sensor','') <> '' ORDER BY x.last_seen DESC LIMIT 1)), attrs->>'exe', attrs->>'unit', attrs->>'container_name', attrs->>'image', last_seen, stopped_at IS NOT NULL
			FROM service_instances i WHERE service_id = $1 AND last_seen > $2 ORDER BY last_seen DESC LIMIT 200`, id, from.Add(-7*24*time.Hour))
		if err != nil {
			appQueryFailed(w, "runtime instances", id, err)
			return
		}
		type inst struct {
			ID            int64           `json:"id"`
			AgentID       string          `json:"agent_id"`
			Host          string          `json:"host"`
			PID           int             `json:"pid"`
			ContainerID   string          `json:"container_id"`
			Listen        json.RawMessage `json:"listen"`
			Instrumented  bool            `json:"instrumented"`
			Identity      string          `json:"identity"`
			Sensor        string          `json:"sensor"`
			Exe           string          `json:"exe"`
			Unit          string          `json:"unit"`
			ContainerName string          `json:"container_name"`
			Image         string          `json:"image"`
			LastSeen      time.Time       `json:"last_seen"`
			Stopped       bool            `json:"stopped"`
		}
		insts := []inst{}
		var pids []int64
		agents := map[string]bool{}
		for irows.Next() {
			var i inst
			var listen []byte
			var sensor, exe, unit, cname, image sql.NullString
			if irows.Scan(&i.ID, &i.AgentID, &i.Host, &i.PID, &i.ContainerID, &listen, &i.Instrumented, &i.Identity, &sensor, &exe, &unit, &cname, &image, &i.LastSeen, &i.Stopped) != nil {
				continue
			}
			i.Listen, i.Sensor, i.Exe = json.RawMessage(listen), sensor.String, exe.String
			i.Unit, i.ContainerName, i.Image = unit.String, cname.String, image.String
			insts = append(insts, i)
			if !i.Stopped && i.PID > 0 {
				pids = append(pids, int64(i.PID))
				agents[i.AgentID] = true
			}
		}
		irows.Close()
		agentList := make([]string, 0, len(agents))
		for a := range agents {
			agentList = append(agentList, a)
		}
		type hostEv struct {
			ID      string          `json:"id"`
			Time    time.Time       `json:"time"`
			Type    string          `json:"type"`
			Source  string          `json:"source"`
			Host    string          `json:"host"`
			PID     int             `json:"pid"`
			PPID    int             `json:"ppid"`
			Process string          `json:"process"`
			Cmd     string          `json:"command_line"`
			User    string          `json:"user"`
			DstIP   string          `json:"dst_ip,omitempty"`
			DstPort int             `json:"dst_port,omitempty"`
			Path    string          `json:"path,omitempty"`
			Proc    json.RawMessage `json:"proc,omitempty"`
		}
		events := []hostEv{}
		counts := map[string]int{}
		if len(pids) > 0 {
			rows, err := idb.QueryContext(ctx, `
				SELECT id, time, event_type, source, host, COALESCE(pid,0), COALESCE(ppid,0), COALESCE(process_name,''), COALESCE(command_line,''),
				       COALESCE(user_name,''), COALESCE(split_part(dst_ip::text, '/', 1),''), COALESCE(dst_port,0), COALESCE(raw->>'path', COALESCE(file_path,'')), raw->'proc'
				FROM events
				WHERE agent_id = ANY($1) AND time >= $2 AND time < $3 AND event_type IN ('process','network','file')
				  AND ($4 = '' OR event_type = $4)
				  AND NOT (event_type = 'network' AND dst_port IN (4317, 4318) AND split_part(dst_ip::text, '/', 1) IN ('127.0.0.1', '::1')) 
				  AND (pid = ANY($5) OR ppid = ANY($5)
				       OR EXISTS (SELECT 1 FROM unnest($5::bigint[]) p WHERE raw->'proc'->'ancestors' @> jsonb_build_array(jsonb_build_object('pid', p))))
				ORDER BY time DESC LIMIT $6`, pq.Array(agentList), from, to, typ, pq.Array(pids), limit)
			if err != nil {
				appQueryFailed(w, "runtime host events", id, err)
				return
			}
			for rows.Next() {
				var e hostEv
				var proc []byte
				if rows.Scan(&e.ID, &e.Time, &e.Type, &e.Source, &e.Host, &e.PID, &e.PPID, &e.Process, &e.Cmd, &e.User, &e.DstIP, &e.DstPort, &e.Path, &proc) == nil {
					e.Proc = json.RawMessage(proc)
					events = append(events, e)
					counts[e.Type]++
				}
			}
			rows.Close()
		}
		writeJSON(w, http.StatusOK, map[string]any{"instances": insts, "events": events, "counts": counts, "from": from, "to": to})
	}
}
