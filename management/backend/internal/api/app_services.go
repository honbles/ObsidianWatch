package api

// app_services.go - service model API (GET list/detail, PUT settings).
// Owned by the Application build. Ingest-created tables are read through
// backendDB; service_settings (management-created) is read and written
// through db. Mutations are admin-only and audited by auditMutations.
// Table shapes follow Application Monitoring Spec v0.2 section 4.

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

var appExposures = map[string]bool{"internet": true, "internal": true, "unknown": true}
var appCriticalities = map[string]bool{"low": true, "normal": true, "high": true, "critical": true}
var appSensitivities = map[string]bool{"normal": true, "sensitive": true, "regulated": true}
var appClientIPModes = map[string]bool{"full": true, "truncated": true, "off": true}

const appMaxListItems = 200

type appMaintenance struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Reason string    `json:"reason,omitempty"`
}

type appServiceSettings struct {
	Exposure          string           `json:"exposure"`
	ExposureInferred  string           `json:"exposure_inferred,omitempty"` // output only: used when exposure is "unknown"
	ExposureReason    string           `json:"exposure_reason,omitempty"`
	ExposureEffective string           `json:"exposure_effective,omitempty"`
	Criticality       string           `json:"criticality"`
	DataSensitivity   string           `json:"data_sensitivity"`
	Owner             string           `json:"owner"`
	NotifyRoute       string           `json:"notify_route"`
	TrustedProxies    []string         `json:"trusted_proxies"`
	LoginRoutes       []string         `json:"login_routes"`
	ExportRoutes      []string         `json:"export_routes"`
	PublicRoutes      []string         `json:"public_routes"`
	LatencyTargetMs   *int             `json:"latency_target_ms"`
	ErrorBudgetPct    *float64         `json:"error_budget_pct"`
	Maintenance       []appMaintenance `json:"maintenance"`
	StoreClientIP     string           `json:"store_client_ip"`
	CleartextUsers    bool             `json:"cleartext_users"`
	DBStatementMode   string           `json:"db_statement_mode"` // off | fingerprint
	LearningStarted   *time.Time       `json:"learning_started"`
	ResetLearning     bool             `json:"reset_learning,omitempty"` // input only
	UpdatedBy         string           `json:"updated_by,omitempty"`
	UpdatedAt         *time.Time       `json:"updated_at,omitempty"`
}

func appDefaultSettings() appServiceSettings {
	return appServiceSettings{
		Exposure: "unknown", Criticality: "normal", DataSensitivity: "normal", StoreClientIP: "full", DBStatementMode: "off",
		TrustedProxies: []string{}, LoginRoutes: []string{}, ExportRoutes: []string{}, PublicRoutes: []string{}, Maintenance: []appMaintenance{},
	}
}

// appServiceKey is the alert-entity / rule-scope key for a service ("name|environment").
func appServiceKey(name, env string) string { return name + "|" + env }

func appCheckStrings(label string, v []string) string {
	if len(v) > appMaxListItems {
		return label + " has too many entries"
	}
	for _, s := range v {
		if s == "" || len(s) > 256 {
			return label + " contains an empty or oversized entry"
		}
	}
	return ""
}

// appValidateSettings checks an update body; it returns "" when valid.
func appValidateSettings(s appServiceSettings) string {
	switch {
	case !appExposures[s.Exposure]:
		return "exposure must be internet, internal or unknown"
	case !appCriticalities[s.Criticality]:
		return "criticality must be low, normal, high or critical"
	case !appSensitivities[s.DataSensitivity]:
		return "data_sensitivity must be normal, sensitive or regulated"
	case !appClientIPModes[s.StoreClientIP]:
		return "store_client_ip must be full, truncated or off"
	case s.DBStatementMode != "" && s.DBStatementMode != "off" && s.DBStatementMode != "fingerprint":
		return "db_statement_mode must be off or fingerprint"
	case len(s.Owner) > 128 || len(s.NotifyRoute) > 256:
		return "owner or notify_route too long"
	case s.LatencyTargetMs != nil && (*s.LatencyTargetMs < 0 || *s.LatencyTargetMs > 600000):
		return "latency_target_ms out of range"
	case s.ErrorBudgetPct != nil && (*s.ErrorBudgetPct < 0 || *s.ErrorBudgetPct > 100):
		return "error_budget_pct must be between 0 and 100"
	case len(s.Maintenance) > 50:
		return "too many maintenance windows"
	}
	for _, c := range s.TrustedProxies {
		if _, _, err := net.ParseCIDR(c); err != nil {
			if net.ParseIP(c) == nil {
				return "trusted_proxies must be CIDRs or addresses"
			}
		}
	}
	for label, v := range map[string][]string{"trusted_proxies": s.TrustedProxies, "login_routes": s.LoginRoutes,
		"export_routes": s.ExportRoutes, "public_routes": s.PublicRoutes} {
		if msg := appCheckStrings(label, v); msg != "" {
			return msg
		}
	}
	for _, m := range s.Maintenance {
		if m.End.Before(m.Start) {
			return "maintenance window ends before it starts"
		}
	}
	return ""
}

func appJSON(v any, def string) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return def
	}
	return string(b)
}

// appSettingsByID loads settings for the given service ids (missing ids get defaults).
func appSettingsByID(ctx context.Context, db *store.DB, ids []int64) map[int64]appServiceSettings {
	out := map[int64]appServiceSettings{}
	if len(ids) == 0 {
		return out
	}
	rows, err := db.QueryContext(ctx, `SELECT service_id, exposure, criticality, data_sensitivity, owner, notify_route,
		trusted_proxies, login_routes, export_routes, public_routes, latency_target_ms, error_budget_pct, maintenance,
		store_client_ip, cleartext_users, learning_started, updated_by, updated_at, db_statement_mode FROM service_settings`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		s := appDefaultSettings()
		var tp, lr, er, pr, mt []byte
		var lat sql.NullInt64
		var bud sql.NullFloat64
		var learn sql.NullTime
		var at time.Time
		if err := rows.Scan(&id, &s.Exposure, &s.Criticality, &s.DataSensitivity, &s.Owner, &s.NotifyRoute,
			&tp, &lr, &er, &pr, &lat, &bud, &mt, &s.StoreClientIP, &s.CleartextUsers, &learn, &s.UpdatedBy, &at, &s.DBStatementMode); err != nil {
			continue
		}
		_ = json.Unmarshal(tp, &s.TrustedProxies)
		_ = json.Unmarshal(lr, &s.LoginRoutes)
		_ = json.Unmarshal(er, &s.ExportRoutes)
		_ = json.Unmarshal(pr, &s.PublicRoutes)
		_ = json.Unmarshal(mt, &s.Maintenance)
		if lat.Valid {
			v := int(lat.Int64)
			s.LatencyTargetMs = &v
		}
		if bud.Valid {
			s.ErrorBudgetPct = &bud.Float64
		}
		if learn.Valid {
			s.LearningStarted = &learn.Time
		}
		s.UpdatedAt = &at
		out[id] = s
	}
	return out
}

func appRange(r *http.Request) (from, to time.Time) {
	to = time.Now().UTC()
	from = to.Add(-24 * time.Hour)
	if v, err := time.Parse(time.RFC3339, r.URL.Query().Get("from")); err == nil {
		from = v
	}
	if v, err := time.Parse(time.RFC3339, r.URL.Query().Get("to")); err == nil {
		to = v
	}
	return from, to
}

var appIngestDBOnce sync.Once

// appIngestDB is the connection application data is read from: the ingest backend's database when one
// is configured, otherwise the management database. Both must hold the application tables (the ingest
// backend writes them), so the choice is logged once.
func appIngestDB(db, backendDB *store.DB) *store.DB {
	if backendDB != nil {
		appIngestDBOnce.Do(func() { slog.Info("application monitoring reads from the ingest (backend) database") })
		return backendDB
	}
	appIngestDBOnce.Do(func() {
		slog.Warn("application monitoring reads from the management database because no separate backend database is configured; this only works when the ingest backend writes to the same database")
	})
	return db
}

// appTier reports the telemetry tier a service has reached from what is known today:
// 0 = discovered only, 1 = OpenTelemetry received. Tier 2 (the service also sent security-helper
// events) is added by appTierWithHelper.
func appTier(source string) int {
	if source == "otel" {
		return 1
	}
	return 0
}

type appServiceRow struct {
	ID            int64              `json:"id"`
	Name          string             `json:"name"`
	Environment   string             `json:"environment"`
	Key           string             `json:"key"`
	Source        string             `json:"source"`
	Tier          int                `json:"tier"`
	FirstSeen     time.Time          `json:"first_seen"`
	LastSeen      time.Time          `json:"last_seen"`
	Attrs         json.RawMessage    `json:"attrs"`
	Instances     int                `json:"instances"`
	Versions      int                `json:"versions"`
	Edges         int                `json:"edges"`
	Routes        int                `json:"routes"`
	Red           *appREDTotals      `json:"red,omitempty"`  // totals for the requested range (list only)
	LearningCalls int64              `json:"learning_calls"` // requests since the learning period started
	Containers    []string           `json:"containers"`     // container names of live instances (list only)
	Images        []string           `json:"images"`
	Units         []string           `json:"units"`
	Hosts         []string           `json:"hosts"`
	Settings      appServiceSettings `json:"settings"`
}

func appHandleListServices(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		from, to := appRange(r)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		env := strings.TrimSpace(r.URL.Query().Get("environment"))
		agent := strings.TrimSpace(r.URL.Query().Get("agent_id")) // services with an instance on this agent's host
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 200
		}
		rows, err := idb.QueryContext(r.Context(), `
			SELECT s.id, s.name, s.environment, s.source, s.first_seen, s.last_seen, s.attrs,
			  (SELECT COUNT(*) FROM service_instances i WHERE i.service_id = s.id AND i.stopped_at IS NULL AND i.last_seen >= $1),
			  (SELECT COUNT(*) FROM service_versions v WHERE v.service_id = s.id),
			  (SELECT COUNT(*) FROM service_edges e WHERE e.src_service = s.id),
			  (SELECT COUNT(*) FROM service_routes r WHERE r.service_id = s.id)
			FROM services s
			WHERE s.last_seen >= $1 AND s.first_seen <= $2
			  AND ($3 = '' OR s.name ILIKE '%' || $3 || '%')
			  AND ($4 = '' OR s.environment = $4)
			  AND ($6 = '' OR EXISTS (SELECT 1 FROM service_instances x WHERE x.service_id = s.id AND x.agent_id = $6))
			ORDER BY s.last_seen DESC LIMIT $5`, from, to, q, env, limit, agent)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		defer rows.Close()
		helpers := appHelperServices(r.Context(), idb)
		list := []appServiceRow{}
		ids := []int64{}
		for rows.Next() {
			var s appServiceRow
			var attrs []byte
			if err := rows.Scan(&s.ID, &s.Name, &s.Environment, &s.Source, &s.FirstSeen, &s.LastSeen, &attrs,
				&s.Instances, &s.Versions, &s.Edges, &s.Routes); err != nil {
				appQueryFailed(w, r.URL.Path, 0, err)
				return
			}
			s.Attrs = json.RawMessage(attrs)
			s.Key = appServiceKey(s.Name, s.Environment)
			s.Tier = appTierWithHelper(s.Source, s.Key, helpers)
			ids = append(ids, s.ID)
			list = append(list, s)
		}
		settings := appSettingsByID(r.Context(), db, ids)
		appApplyExposure(r.Context(), idb, ids, settings)
		totals := appServiceTotals(r.Context(), idb, ids, from, to)
		learn := appLearningCalls(r.Context(), idb, ids, settings)
		loc := appLocators(r.Context(), idb, ids, from)
		for i := range list {
			list[i].LearningCalls = learn[list[i].ID]
			l := loc[list[i].ID]
			list[i].Containers, list[i].Images, list[i].Units, list[i].Hosts = nonNil(l.containers), nonNil(l.images), nonNil(l.units), nonNil(l.hosts)
			if t, ok := totals[list[i].ID]; ok {
				t := t
				list[i].Red = &t
			}
			if st, ok := settings[list[i].ID]; ok {
				list[i].Settings = st
			} else {
				list[i].Settings = appDefaultSettings()
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"services": list, "from": from, "to": to})
	}
}

func appHandleGetService(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var s appServiceRow
		var attrs []byte
		err = idb.QueryRowContext(r.Context(),
			`SELECT id, name, environment, source, first_seen, last_seen, attrs FROM services WHERE id = $1`, id).
			Scan(&s.ID, &s.Name, &s.Environment, &s.Source, &s.FirstSeen, &s.LastSeen, &attrs)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
		}
		s.Attrs = json.RawMessage(attrs)
		s.Key = appServiceKey(s.Name, s.Environment)
		s.Tier = appTierWithHelper(s.Source, s.Key, appHelperServices(r.Context(), idb))

		type inst struct {
			ID           int64           `json:"id"`
			AgentID      string          `json:"agent_id"`
			Host         string          `json:"host"`
			ContainerID  string          `json:"container_id"`
			PID          int             `json:"pid"`
			ProcStart    time.Time       `json:"proc_start"`
			InstanceRef  string          `json:"instance_ref"`
			Version      string          `json:"version"`
			Listen       json.RawMessage `json:"listen"`
			Instrumented bool            `json:"instrumented"`
			Identity     string          `json:"identity"`
			Attrs        json.RawMessage `json:"attrs"`
			FirstSeen    time.Time       `json:"first_seen"`
			LastSeen     time.Time       `json:"last_seen"`
			StoppedAt    *time.Time      `json:"stopped_at"`
		}
		instances := []inst{}
		if rows, err := idb.QueryContext(r.Context(), `SELECT id, agent_id, host, container_id, pid, proc_start, instance_ref, version,
			listen, instrumented, identity, attrs, first_seen, last_seen, stopped_at
			FROM service_instances WHERE service_id = $1 ORDER BY last_seen DESC LIMIT 500`, id); err == nil {
			for rows.Next() {
				var i inst
				var listen, iattrs []byte
				var stopped sql.NullTime
				if rows.Scan(&i.ID, &i.AgentID, &i.Host, &i.ContainerID, &i.PID, &i.ProcStart, &i.InstanceRef, &i.Version,
					&listen, &i.Instrumented, &i.Identity, &iattrs, &i.FirstSeen, &i.LastSeen, &stopped) == nil {
					i.Listen, i.Attrs = json.RawMessage(listen), json.RawMessage(iattrs)
					if stopped.Valid {
						i.StoppedAt = &stopped.Time
					}
					instances = append(instances, i)
				}
			}
			rows.Close()
		}
		type ver struct {
			Version   string    `json:"version"`
			FirstSeen time.Time `json:"first_seen"`
			LastSeen  time.Time `json:"last_seen"`
			Instances int       `json:"instances"`
		}
		versions := []ver{}
		if rows, err := idb.QueryContext(r.Context(), `SELECT version, first_seen, last_seen, instances FROM service_versions WHERE service_id = $1 ORDER BY first_seen DESC LIMIT 100`, id); err == nil {
			for rows.Next() {
				var v ver
				if rows.Scan(&v.Version, &v.FirstSeen, &v.LastSeen, &v.Instances) == nil {
					versions = append(versions, v)
				}
			}
			rows.Close()
		}
		type edge struct {
			DstKind             string    `json:"dst_kind"`
			DstName             string    `json:"dst_name"`
			ResolvedServiceID   int64     `json:"resolved_service_id,omitempty"` // local port linked to a discovered service
			ResolvedServiceName string    `json:"resolved_service_name,omitempty"`
			Source              string    `json:"source"`
			Calls               int64     `json:"calls"`
			Errors              int64     `json:"errors"`
			FirstSeen           time.Time `json:"first_seen"`
			LastSeen            time.Time `json:"last_seen"`
		}
		edges := []edge{}
		var localIx *appLocalIndex
		if rows, err := idb.QueryContext(r.Context(), `SELECT dst_kind, dst_name, source, calls, errors, first_seen, last_seen FROM service_edges WHERE src_service = $1 ORDER BY calls DESC LIMIT 500`, id); err == nil {
			for rows.Next() {
				var e edge
				if rows.Scan(&e.DstKind, &e.DstName, &e.Source, &e.Calls, &e.Errors, &e.FirstSeen, &e.LastSeen) == nil {
					if localIx == nil {
						localIx = appLoadLocalIndex(r.Context(), idb)
					}
					if t, ok := localIx.Resolve(id, e.DstName); ok && e.DstKind != "service" {
						e.ResolvedServiceID, e.ResolvedServiceName = t.ServiceID, t.Name
					}
					edges = append(edges, e)
				}
			}
			rows.Close()
		}

		s.Settings = appDefaultSettings()
		sm := appSettingsByID(r.Context(), db, []int64{id})
		appApplyExposure(r.Context(), idb, []int64{id}, sm)
		if st, ok := sm[id]; ok {
			s.Settings = st
		}
		s.LearningCalls = appLearningCalls(r.Context(), idb, []int64{id}, sm)[id]
		for _, i := range instances {
			if i.StoppedAt == nil {
				s.Instances++
			}
		}
		s.Versions, s.Edges = len(versions), len(edges)
		writeJSON(w, http.StatusOK, map[string]any{"service": s, "instances": instances, "versions": versions, "edges": edges})
	}
}

func appHandlePutServiceSettings(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var name, env string
		if err := idb.QueryRowContext(r.Context(), `SELECT name, environment FROM services WHERE id = $1`, id).Scan(&name, &env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
		}
		body := appDefaultSettings()
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		body.Owner, body.NotifyRoute = strings.TrimSpace(body.Owner), strings.TrimSpace(body.NotifyRoute)
		for _, p := range []*[]string{&body.TrustedProxies, &body.LoginRoutes, &body.ExportRoutes, &body.PublicRoutes} {
			if *p == nil {
				*p = []string{}
			}
		}
		if body.Maintenance == nil {
			body.Maintenance = []appMaintenance{}
		}
		if msg := appValidateSettings(body); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		dbMode := body.DBStatementMode
		if dbMode == "" {
			dbMode = "off"
		}
		body.DBStatementMode = dbMode
		// learning_started: keep what is stored unless the analyst asks to restart learning.
		var learn any
		if body.ResetLearning {
			learn = time.Now().UTC()
		} else {
			learn = body.LearningStarted
		}
		if _, err := db.ExecContext(r.Context(), `
			INSERT INTO service_settings (service_id, exposure, criticality, data_sensitivity, owner, notify_route,
			  trusted_proxies, login_routes, export_routes, public_routes, latency_target_ms, error_budget_pct, maintenance,
			  store_client_ip, cleartext_users, learning_started, updated_by, updated_at, db_statement_mode)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,$11,$12,$13::jsonb,$14,$15,$16,$17,NOW(),$18)
			ON CONFLICT (service_id) DO UPDATE SET exposure=EXCLUDED.exposure, criticality=EXCLUDED.criticality,
			  data_sensitivity=EXCLUDED.data_sensitivity, owner=EXCLUDED.owner, notify_route=EXCLUDED.notify_route,
			  trusted_proxies=EXCLUDED.trusted_proxies, login_routes=EXCLUDED.login_routes, export_routes=EXCLUDED.export_routes,
			  public_routes=EXCLUDED.public_routes, latency_target_ms=EXCLUDED.latency_target_ms,
			  error_budget_pct=EXCLUDED.error_budget_pct, maintenance=EXCLUDED.maintenance,
			  store_client_ip=EXCLUDED.store_client_ip, cleartext_users=EXCLUDED.cleartext_users,
			  learning_started=COALESCE(EXCLUDED.learning_started, service_settings.learning_started),
			  updated_by=EXCLUDED.updated_by, updated_at=NOW(), db_statement_mode=EXCLUDED.db_statement_mode`,
			id, body.Exposure, body.Criticality, body.DataSensitivity, body.Owner, body.NotifyRoute,
			appJSON(body.TrustedProxies, "[]"), appJSON(body.LoginRoutes, "[]"), appJSON(body.ExportRoutes, "[]"), appJSON(body.PublicRoutes, "[]"),
			body.LatencyTargetMs, body.ErrorBudgetPct, appJSON(body.Maintenance, "[]"),
			body.StoreClientIP, body.CleartextUsers, learn, by, dbMode); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "save failed"})
			return
		}
		body.UpdatedBy, body.ResetLearning = by, false
		writeJSON(w, http.StatusOK, map[string]any{"key": appServiceKey(name, env), "settings": body})
	}
}

type appLocator struct{ containers, images, units, hosts []string }

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// appLocators lists where each service runs: the container names, images and systemd units of its live
// instances, and the hosts they are on (spec B2: the host alone is not enough to find a workload).
func appLocators(ctx context.Context, idb *store.DB, ids []int64, since time.Time) map[int64]appLocator {
	out := map[int64]appLocator{}
	if len(ids) == 0 {
		return out
	}
	rows, err := idb.QueryContext(ctx, `
		SELECT service_id,
		  array_remove(array_agg(DISTINCT NULLIF(attrs->>'container_name','')), NULL),
		  array_remove(array_agg(DISTINCT NULLIF(attrs->>'image','')), NULL),
		  array_remove(array_agg(DISTINCT NULLIF(attrs->>'unit','')), NULL),
		  array_remove(array_agg(DISTINCT NULLIF(host,'')), NULL)
		FROM service_instances WHERE service_id = ANY($1) AND stopped_at IS NULL AND last_seen >= $2 GROUP BY service_id`, pq.Array(ids), since)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var c, i, u, h pq.StringArray
		if rows.Scan(&id, &c, &i, &u, &h) == nil {
			out[id] = appLocator{containers: c, images: i, units: u, hosts: h}
		}
	}
	return out
}
