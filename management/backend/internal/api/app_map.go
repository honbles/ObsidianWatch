package api

// app_map.go - GET /api/v1/app/map: the estate dependency graph (spec 11.3 Dependencies).
// Owned by the Application build. Nodes are services (resolved by name from peer.service) plus
// databases, queues and external destinations; edges carry calls and errors in the range from
// the hourly app_edge_stats, and a "new" flag for dependencies first seen inside the range
// (an edge on a service's first day is baseline, not a change).

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type appMapNode struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // service | database | queue | external
	Name        string `json:"name"`
	ServiceID   int64  `json:"service_id,omitempty"`
	Environment string `json:"environment,omitempty"`
	Key         string `json:"key,omitempty"`
	Tier        int    `json:"tier,omitempty"`
	Exposure    string `json:"exposure,omitempty"`
	Criticality string `json:"criticality,omitempty"`
	// ReachableFromInternet is true for services an internet-facing service can reach through
	// service-to-service calls (an internet-facing service is trivially reachable).
	ReachableFromInternet bool `json:"reachable_from_internet,omitempty"`
}

type appMapEdge struct {
	Source string    `json:"source"`
	Target string    `json:"target"`
	Kind   string    `json:"kind"`
	Via    string    `json:"via"`
	Calls  int64     `json:"calls"`
	Errors int64     `json:"errors"`
	New    bool      `json:"new"`
	First  time.Time `json:"first_seen"`
}

func appMapID(kind, name string) string { return kind + ":" + name }

func appHandleMap(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		from, to, msg := appParseRange(r)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		ctx := r.Context()
		srows, err := idb.QueryContext(ctx, `SELECT id, name, environment, source, first_seen FROM services WHERE last_seen >= $1 ORDER BY name, environment LIMIT 500`, from)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		type svcRow struct {
			node  appMapNode
			first time.Time
		}
		svcs := map[int64]*svcRow{}
		var ids []int64
		helpers := appHelperServices(r.Context(), idb)
		byName := map[string][]int64{}
		for srows.Next() {
			var id int64
			var n, env, src string
			var first time.Time
			if srows.Scan(&id, &n, &env, &src, &first) != nil {
				continue
			}
			svcs[id] = &svcRow{node: appMapNode{ID: appMapID("service", appServiceKey(n, env)), Type: "service", Name: n, ServiceID: id,
				Environment: env, Key: appServiceKey(n, env), Tier: appTierWithHelper(src, appServiceKey(n, env), helpers)}, first: first}
			ids = append(ids, id)
			byName[n] = append(byName[n], id)
		}
		srows.Close()
		settings := appSettingsByID(ctx, db, ids)
		appApplyExposure(ctx, idb, ids, settings)
		for id, s := range svcs {
			st, ok := settings[id]
			if !ok {
				st = appDefaultSettings()
			}
			s.node.Exposure, s.node.Criticality = st.EffectiveExposure(), st.Criticality
		}

		erows, err := idb.QueryContext(ctx, `
			SELECT e.src_service, e.dst_kind, e.dst_name, e.source, e.first_seen, COALESCE(h.calls,0), COALESCE(h.errors,0)
			FROM service_edges e
			LEFT JOIN (SELECT src_service, dst_kind, dst_name, source, SUM(calls) AS calls, SUM(errors) AS errors
			           FROM app_edge_stats WHERE hour >= $1 AND hour < $2 GROUP BY 1,2,3,4) h
			  USING (src_service, dst_kind, dst_name, source)
			WHERE e.last_seen >= $3
			ORDER BY COALESCE(h.calls,0) DESC LIMIT 2000`, from.Truncate(time.Hour), to, from)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		nodes := map[string]*appMapNode{}
		localIx := appLoadLocalIndex(ctx, idb)
		for _, s := range svcs {
			n := s.node
			nodes[n.ID] = &n
		}
		var edges []appMapEdge
		for erows.Next() {
			var src int64
			var kind, dst, via string
			var first time.Time
			var calls, errs int64
			if erows.Scan(&src, &kind, &dst, &via, &first, &calls, &errs) != nil {
				continue
			}
			s, ok := svcs[src]
			if !ok {
				continue
			}
			target := appMapID(kind, dst)
			if kind != "service" {
				if t, ok := localIx.Resolve(src, dst); ok {
					if ts, ok := svcs[t.ServiceID]; ok { // the service listening on that local port
						kind, target = "service", ts.node.ID
					}
				}
			}
			if kind == "service" && target == appMapID(kind, dst) { // peer.service names a service: resolve it, same environment first
				if cands := byName[dst]; len(cands) > 0 {
					pick := cands[0]
					for _, c := range cands {
						if svcs[c].node.Environment == s.node.Environment {
							pick = c
							break
						}
					}
					target = svcs[pick].node.ID
				}
			}
			if _, ok := nodes[target]; !ok {
				nodes[target] = &appMapNode{ID: target, Type: kind, Name: dst}
			}
			edges = append(edges, appMapEdge{Source: s.node.ID, Target: target, Kind: kind, Via: via, Calls: calls, Errors: errs,
				First: first, New: !first.Before(from) && first.After(s.first.Add(time.Hour))})
		}
		erows.Close()

		// Reachability from internet-facing services over service-to-service edges.
		adj := map[string][]string{}
		for _, e := range edges {
			if strings.HasPrefix(e.Target, "service:") {
				adj[e.Source] = append(adj[e.Source], e.Target)
			}
		}
		var queue []string
		for id, n := range nodes {
			if n.Type == "service" && n.Exposure == "internet" {
				n.ReachableFromInternet = true
				queue = append(queue, id)
			}
		}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, nx := range adj[cur] {
				if t := nodes[nx]; t != nil && !t.ReachableFromInternet {
					t.ReachableFromInternet = true
					queue = append(queue, nx)
				}
			}
		}

		out := make([]appMapNode, 0, len(nodes))
		for _, n := range nodes {
			out = append(out, *n)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		if edges == nil {
			edges = []appMapEdge{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "nodes": out, "edges": edges})
	}
}
