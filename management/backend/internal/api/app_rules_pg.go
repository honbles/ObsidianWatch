package api

// app_rules_pg.go - appData over the shared PostgreSQL database. Ingest-created tables
// (services, service_instances, app_baselines, app_route_stats, app_client_stats, events,
// agents) are read through backendDB; service_settings, alerts and ioc_indicators through db.
// The baseline table is also written here: it belongs to the ingest migration but only the rules write it.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"obsidianwatch/management/internal/store"
)

type appPGData struct {
	db  *store.DB // management tables
	idb *store.DB // ingest tables
}

const appInstanceFresh = 7 * 24 * time.Hour // an instance counts as live if it reported within a week

func (d appPGData) ServiceForLineage(ctx context.Context, agentID, containerID string, pids []int) (appSvc, appInst, int, bool) {
	var none appSvc
	var pidArr []int64
	for _, p := range pids {
		if p > 0 {
			pidArr = append(pidArr, int64(p))
		}
	}
	rows, err := d.idb.QueryContext(ctx, `
		SELECT i.id, i.service_id, i.agent_id, i.host, i.pid, i.proc_start, i.container_id, i.identity, i.version, i.instance_ref,
		       i.first_seen, i.last_seen, COALESCE(i.attrs->>'exe',''),
		       s.name, s.environment, s.source, s.first_seen
		FROM service_instances i JOIN services s ON s.id = i.service_id
		WHERE i.agent_id = $1 AND i.stopped_at IS NULL AND i.last_seen > $4
		  AND ((i.pid > 0 AND i.pid = ANY($2)) OR ($3 <> '' AND i.container_id = $3))`,
		agentID, pq.Array(pidArr), containerID, time.Now().Add(-appInstanceFresh))
	if err != nil {
		return none, appInst{}, 0, false
	}
	defer rows.Close()
	best := -1
	var bs appSvc
	var bi appInst
	for rows.Next() {
		var i appInst
		var s appSvc
		var exe string
		if rows.Scan(&i.ID, &i.ServiceID, &i.AgentID, &i.Host, &i.PID, &i.ProcStart, &i.ContainerID, &i.Identity, &i.Version, &i.Ref,
			&i.FirstSeen, &i.LastSeen, &exe, &s.Name, &s.Env, &s.Source, &s.FirstSeen) != nil {
			continue
		}
		s.ID, i.Name = i.ServiceID, appBaseName(exe)
		idx := -1
		for k, p := range pids {
			if p > 0 && p == i.PID {
				idx = k
				break
			}
		}
		if idx < 0 { // matched by container only: the process is in the service's container
			idx = 0
		}
		if best < 0 || idx < best {
			best, bs, bi = idx, s, i
		}
	}
	if best < 0 {
		return none, appInst{}, 0, false
	}
	bs.Settings = d.settings(ctx, bs.ID)
	return bs, bi, best, true
}

func (d appPGData) settings(ctx context.Context, id int64) appServiceSettings {
	sm := appSettingsByID(ctx, d.db, []int64{id})
	appApplyExposure(ctx, d.idb, []int64{id}, sm)
	if st, ok := sm[id]; ok {
		return st
	}
	return appDefaultSettings()
}

func (d appPGData) Baseline(ctx context.Context, svcID int64, kind, key string) (bool, error) {
	var one int
	err := d.idb.QueryRowContext(ctx, `SELECT 1 FROM app_baselines WHERE service_id=$1 AND kind=$2 AND key=$3`, svcID, kind, key).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (d appPGData) RecordBaseline(ctx context.Context, svcID int64, kind, key string, now time.Time) error {
	_, err := d.idb.ExecContext(ctx, `
		INSERT INTO app_baselines (service_id, kind, key, samples, first_seen, updated) VALUES ($1,$2,$3,1,$4,$4)
		ON CONFLICT (service_id, kind, key) DO UPDATE SET samples = app_baselines.samples + 1, updated = EXCLUDED.updated`,
		svcID, kind, key, now)
	return err
}

func (d appPGData) BaselineSamples(ctx context.Context, svcID int64, kind string) (int64, error) {
	var n int64
	err := d.idb.QueryRowContext(ctx, `SELECT COALESCE(SUM(samples),0) FROM app_baselines WHERE service_id=$1 AND kind=$2 AND key NOT LIKE 'dnsdom:%'`, svcID, kind).Scan(&n)
	return n, err
}

// InDeployWindow: a new version appeared in the window, or an instance started in it while the
// host ran a package manager (spec 10.1). The first version of a service is its baseline, not a deploy.
func (d appPGData) InDeployWindow(ctx context.Context, svc appSvc, agentID string, now time.Time, window time.Duration) bool {
	var one int
	err := d.idb.QueryRowContext(ctx, `
		SELECT 1 FROM service_versions WHERE service_id=$1 AND first_seen > $2 AND first_seen <= $3 AND first_seen > $4 LIMIT 1`,
		svc.ID, now.Add(-window), now, svc.FirstSeen.Add(time.Hour)).Scan(&one)
	if err == nil {
		return true
	}
	if agentID == "" {
		return false
	}
	err = d.idb.QueryRowContext(ctx, `
		SELECT 1 FROM service_instances WHERE service_id=$1 AND agent_id=$2 AND first_seen > $3 AND first_seen <= $4 AND first_seen > $5 LIMIT 1`,
		svc.ID, agentID, now.Add(-window), now, svc.FirstSeen.Add(time.Hour)).Scan(&one)
	if err != nil {
		return false
	}
	err = d.idb.QueryRowContext(ctx, `
		SELECT 1 FROM events WHERE agent_id=$1 AND event_type='process' AND time > $2 AND time <= $3
		  AND lower(process_name) = ANY($4) LIMIT 1`,
		agentID, now.Add(-window), now, pq.Array([]string{"apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "apk", "zypper", "pip", "pip3", "npm", "yarn", "helm", "kubectl", "docker", "ansible", "ansible-playbook", "puppet", "chef-client", "salt-minion"})).Scan(&one)
	return err == nil
}

func (d appPGData) IPIntel(ctx context.Context, ip string) (string, bool) {
	ioc, err := d.db.MatchIOC(ctx, "ip", ip)
	if err != nil || ioc == nil {
		return "", false
	}
	return ioc.Source, true
}

// AppAnomaly reports application-side evidence for X02: an A09 alert for the service, or a 5xx spike.
func (d appPGData) AppAnomaly(ctx context.Context, svc appSvc, since time.Time, spike5xx int64) (string, bool) {
	var n int
	_ = d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE event_id LIKE $1 AND created_at >= $2`,
		fmt.Sprintf("app:APP-A09:%d:%%", svc.ID), since).Scan(&n)
	if n > 0 {
		return "Injection attempts against this service were detected", true
	}
	var fives int64
	_ = d.idb.QueryRowContext(ctx, `SELECT COALESCE(SUM(status_5xx),0) FROM app_route_stats WHERE service_id=$1 AND minute >= $2`, svc.ID, since).Scan(&fives)
	if fives >= spike5xx {
		return fmt.Sprintf("A spike of %d server errors (5xx) hit this service", fives), true
	}
	return "", false
}

func (d appPGData) ActiveServices(ctx context.Context, since time.Time) ([]appSvc, error) {
	rows, err := d.idb.QueryContext(ctx, `SELECT id, name, environment, source, first_seen FROM services WHERE last_seen >= $1 ORDER BY id LIMIT 2000`, since)
	if err != nil {
		return nil, err
	}
	var out []appSvc
	var ids []int64
	for rows.Next() {
		var s appSvc
		if rows.Scan(&s.ID, &s.Name, &s.Env, &s.Source, &s.FirstSeen) == nil {
			out = append(out, s)
			ids = append(ids, s.ID)
		}
	}
	rows.Close()
	st := appSettingsByID(ctx, d.db, ids)
	appApplyExposure(ctx, d.idb, ids, st)
	for i := range out {
		if s, ok := st[out[i].ID]; ok {
			out[i].Settings = s
		} else {
			out[i].Settings = appDefaultSettings()
		}
	}
	return out, nil
}

func (d appPGData) ClientRows(ctx context.Context, svcID int64, since time.Time) ([]appClientRow, error) {
	rows, err := d.idb.QueryContext(ctx, `
		SELECT minute, route, method, client_ip, peer_ip, exc_type, failures, status_401_403, status_429, status_4xx_other, status_5xx
		FROM app_client_stats WHERE service_id=$1 AND minute >= $2 ORDER BY minute LIMIT 50000`, svcID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []appClientRow
	for rows.Next() {
		var r appClientRow
		if rows.Scan(&r.Minute, &r.Route, &r.Method, &r.ClientIP, &r.PeerIP, &r.ExcType, &r.Failures, &r.Status40103, &r.Status429, &r.Status4xxOther, &r.Status5xx) == nil {
			out = append(out, r)
		}
	}
	return out, nil
}

func (d appPGData) NewRoutes(ctx context.Context, svcID int64, since time.Time) ([]appRouteRef, error) {
	rows, err := d.idb.QueryContext(ctx, `SELECT route, method, first_seen FROM service_routes WHERE service_id=$1 AND first_seen >= $2 ORDER BY first_seen LIMIT 200`, svcID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []appRouteRef
	for rows.Next() {
		var r appRouteRef
		if rows.Scan(&r.Route, &r.Method, &r.FirstSeen) == nil {
			out = append(out, r)
		}
	}
	return out, nil
}

func (d appPGData) Requests(ctx context.Context, svc appSvc) (int64, error) {
	return appLearningCalls(ctx, d.idb, []int64{svc.ID}, map[int64]appServiceSettings{svc.ID: svc.Settings})[svc.ID], nil
}

func (d appPGData) RouteWindow(ctx context.Context, svcID int64, from, to time.Time) ([]appWindowStats, error) {
	rows, err := d.idb.QueryContext(ctx, `
		SELECT route, method, SUM(calls), SUM(errors) FROM app_route_stats WHERE service_id=$1 AND minute >= $2 AND minute < $3 GROUP BY route, method`, svcID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []appWindowStats
	for rows.Next() {
		var s appWindowStats
		if rows.Scan(&s.Route, &s.Method, &s.Calls, &s.Errors) == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

func (d appPGData) Instances(ctx context.Context, svcID int64) ([]appInst, error) {
	rows, err := d.idb.QueryContext(ctx, `
		SELECT id, service_id, agent_id, host, pid, proc_start, container_id, identity, version, instance_ref, first_seen, last_seen, stopped_at IS NOT NULL
		FROM service_instances WHERE service_id=$1 AND last_seen > $2 ORDER BY id LIMIT 500`, svcID, time.Now().Add(-appInstanceFresh))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []appInst
	for rows.Next() {
		var i appInst
		if rows.Scan(&i.ID, &i.ServiceID, &i.AgentID, &i.Host, &i.PID, &i.ProcStart, &i.ContainerID, &i.Identity, &i.Version, &i.Ref, &i.FirstSeen, &i.LastSeen, &i.Stopped) == nil {
			out = append(out, i)
		}
	}
	return out, nil
}

func (d appPGData) AgentSeen(ctx context.Context, agentID string) (time.Time, error) {
	var t time.Time
	err := d.idb.QueryRowContext(ctx, `SELECT last_seen FROM agents WHERE id=$1`, agentID).Scan(&t)
	return t, err
}

func (d appPGData) ProcessAlive(ctx context.Context, agentID string, pid int, since time.Time) (bool, error) {
	var one int
	err := d.idb.QueryRowContext(ctx, `SELECT 1 FROM events WHERE agent_id=$1 AND pid=$2 AND time > $3 LIMIT 1`, agentID, pid, since).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (d appPGData) LastRequestMinute(ctx context.Context, svcID int64) (time.Time, error) {
	var t sql.NullTime
	err := d.idb.QueryRowContext(ctx, `SELECT MAX(minute) FROM app_route_stats WHERE service_id=$1`, svcID).Scan(&t)
	return t.Time, err
}
