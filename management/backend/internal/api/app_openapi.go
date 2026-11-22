package api

// app_openapi.go - declare a service's API from an OpenAPI / Swagger document so its routes and fields can be
// reviewed and masked before any traffic arrives (payload design, "declared" routes).
//
//	GET    /api/v1/app/services/{id}/openapi   what is loaded
//	POST   /api/v1/app/services/{id}/openapi   {"spec": "<document text>"} or {"url": "https://..."} and optional "base_path"
//	DELETE /api/v1/app/services/{id}/openapi   forget the declared routes and fields
//
// All three are admin only. Declared fields are stored in service_route_params with source "declared" and no
// requests; fields seen later become "both", and fields the document does not list stay "observed", which the
// Routes tab flags as undocumented.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// appBlockedIP reports addresses the server must never fetch a spec from: loopback (this server itself),
// link-local (cloud metadata), unspecified and multicast. Private ranges are allowed because the application
// is normally on one.
func appBlockedIP(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// appSpecClient fetches with a dialer that checks the address actually dialled, so a redirect or a DNS answer
// cannot reach a blocked address.
func appSpecClient() *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if appBlockedIP(net.ParseIP(host)) {
			return errors.New("that address is not allowed (loopback, link-local or unspecified)")
		}
		return nil
	}}
	return &http.Client{
		Timeout:   12 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext, Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

func appFetchSpec(ctx context.Context, raw string) ([]byte, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("the URL must be http or https, with a host and no credentials")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && appBlockedIP(ip) {
		return nil, errors.New("that address is not allowed (loopback, link-local or unspecified)")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*;q=0.5")
	resp, err := appSpecClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch the document: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the server answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, appSpecMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("could not read the document: %v", err)
	}
	return b, nil
}

type appOpenAPIInfo struct {
	Loaded    bool      `json:"loaded"`
	Title     string    `json:"title,omitempty"`
	Version   string    `json:"version,omitempty"`
	Source    string    `json:"source,omitempty"`
	Routes    int       `json:"routes"`
	Params    int       `json:"params"`
	Matched   int       `json:"matched,omitempty"` // declared routes that already had traffic
	LoadedBy  string    `json:"loaded_by,omitempty"`
	LoadedAt  time.Time `json:"loaded_at,omitempty"`
	Truncated int       `json:"skipped_routes,omitempty"`
}

func appHandleGetOpenAPI(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		writeJSON(w, http.StatusOK, appLoadOpenAPIInfo(r.Context(), idb, id))
	}
}

func appLoadOpenAPIInfo(ctx context.Context, idb *store.DB, id int64) appOpenAPIInfo {
	info := appOpenAPIInfo{}
	err := idb.QueryRowContext(ctx, `SELECT title, version, source_ref, routes, params, loaded_by, loaded_at FROM service_openapi WHERE service_id=$1`, id).
		Scan(&info.Title, &info.Version, &info.Source, &info.Routes, &info.Params, &info.LoadedBy, &info.LoadedAt)
	info.Loaded = err == nil
	return info
}

func appHandleLoadOpenAPI(db, backendDB *store.DB) http.HandlerFunc {
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
		var body struct {
			Spec     string `json:"spec"`
			URL      string `json:"url"`
			BasePath string `json:"base_path"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, appSpecMaxBytes+4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request (a document larger than 5 MB is refused)"})
			return
		}
		if (body.Spec == "") == (strings.TrimSpace(body.URL) == "") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "send either the document text (spec) or a URL, not both and not neither"})
			return
		}
		raw, source := []byte(body.Spec), "upload"
		if body.URL != "" {
			if raw, err = appFetchSpec(r.Context(), body.URL); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			source = strings.TrimSpace(body.URL)
			if len(source) > 300 {
				source = source[:300]
			}
		}
		api, err := appParseOpenAPI(raw, body.BasePath)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		info, err := appStoreDeclared(r.Context(), idb, id, api, source, by)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		slog.Info("application API spec loaded", "service", name, "environment", env, "by", by, "source", source,
			"routes", info.Routes, "fields", info.Params, "matched", info.Matched)
		writeJSON(w, http.StatusOK, info)
	}
}

// appStoreDeclared replaces the declared routes and fields of a service. A declared route that matches a route
// already observed (same method and shape) is stored under the observed template, so the two are one route.
func appStoreDeclared(ctx context.Context, idb *store.DB, id int64, api *appDeclaredAPI, source, by string) (appOpenAPIInfo, error) {
	tx, err := idb.BeginTx(ctx, nil)
	if err != nil {
		return appOpenAPIInfo{}, err
	}
	defer tx.Rollback()
	if err := appClearDeclared(ctx, tx, id); err != nil {
		return appOpenAPIInfo{}, err
	}
	observed := map[string]string{} // METHOD shape -> observed route template
	rows, err := tx.QueryContext(ctx, `SELECT route, method FROM service_routes WHERE service_id=$1`, id)
	if err != nil {
		return appOpenAPIInfo{}, err
	}
	for rows.Next() {
		var route, method string
		if rows.Scan(&route, &method) == nil {
			observed[method+" "+appRouteShape(route)] = route
		}
	}
	rows.Close()

	info := appOpenAPIInfo{Loaded: true, Title: api.Title, Version: api.Version, Source: source, LoadedBy: by, LoadedAt: time.Now(), Truncated: api.Skipped}
	for _, dr := range api.Routes {
		route := dr.Route
		if o, ok := observed[dr.Method+" "+appRouteShape(route)]; ok {
			route = o
			info.Matched++
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO service_declared_routes (service_id, route, method, summary) VALUES ($1,$2,$3,$4)
			ON CONFLICT (service_id, route, method) DO UPDATE SET summary = EXCLUDED.summary, declared_at = NOW()`,
			id, route, dr.Method, dr.Summary); err != nil {
			return info, err
		}
		info.Routes++
		for _, f := range dr.Fields {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen, source, location)
				VALUES ($1,$2,$3,$4,0,NOW(),NOW(),'declared',$5)
				ON CONFLICT (service_id, route, method, name) DO UPDATE SET
				  source = CASE WHEN service_route_params.source = 'observed' THEN 'both' ELSE service_route_params.source END,
				  location = EXCLUDED.location`, id, route, dr.Method, f.Name, f.Location); err != nil {
				return info, err
			}
			info.Params++
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO service_openapi (service_id, title, version, source_ref, routes, params, loaded_by, loaded_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
		ON CONFLICT (service_id) DO UPDATE SET title=EXCLUDED.title, version=EXCLUDED.version, source_ref=EXCLUDED.source_ref,
		  routes=EXCLUDED.routes, params=EXCLUDED.params, loaded_by=EXCLUDED.loaded_by, loaded_at=NOW()`,
		id, info.Title, info.Version, info.Source, info.Routes, info.Params, by); err != nil {
		return info, err
	}
	return info, tx.Commit()
}

// appClearDeclared removes everything a spec declared: fields seen only in the spec disappear, fields also seen
// in traffic go back to "observed".
func appClearDeclared(ctx context.Context, tx *sql.Tx, id int64) error {
	for _, q := range []string{
		`DELETE FROM service_route_params WHERE service_id=$1 AND source='declared'`,
		`UPDATE service_route_params SET source='observed', location='' WHERE service_id=$1 AND source='both'`,
		`DELETE FROM service_declared_routes WHERE service_id=$1`,
		`DELETE FROM service_openapi WHERE service_id=$1`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return nil
}

func appHandleDeleteOpenAPI(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		tx, err := idb.BeginTx(r.Context(), nil)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		defer tx.Rollback()
		if err := appClearDeclared(r.Context(), tx, id); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		if err := tx.Commit(); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		slog.Info("application API spec removed", "service_id", id, "by", by)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}
