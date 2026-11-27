package api

// app_code_autolink.go - a service that reports where its source lives (the OpenTelemetry resource attribute
// vcs.repository.url.full, or git.repository_url) is linked to that repository automatically, when the
// repository belongs to a connected code platform and the service has no link yet. An analyst's links are
// never changed; an automatic link can be removed like any other.

import (
	"context"
	"net/url"
	"strings"

	"obsidianwatch/management/internal/store"
)

// repoRef splits a reported repository URL into host and lower-case path: "https://github.com/Acme/Api.git",
// "git@github.com:acme/api" and "github.com/acme/api" all give ("github.com", "acme/api").
func repoRef(raw string) (host, path string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}
	if !strings.Contains(s, "://") {
		if at := strings.Index(s, "@"); at >= 0 && strings.Contains(s[at:], ":") { // scp-like git@host:org/repo
			s = "ssh://" + strings.Replace(s[at+1:], ":", "/", 1)
		} else {
			s = "https://" + s
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", ""
	}
	p := strings.Trim(strings.ToLower(u.Path), "/")
	p = strings.TrimSuffix(p, ".git")
	return strings.ToLower(u.Hostname()), p
}

// connectorHost is the host a code platform connector's repositories live on.
func connectorHost(c store.DevOpsConnector) string {
	if b := c.Credentials["base_url"]; b != "" {
		if u, err := url.Parse(b); err == nil && u.Host != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	switch strings.ToLower(c.Provider) {
	case "github":
		return "github.com"
	case "gitlab":
		return "gitlab.com"
	case "azure", "azure_devops", "azuredevops":
		return "dev.azure.com"
	}
	return ""
}

// appAutoLinkCode links service id to the repository its instances report, if it has no link yet. It returns
// true when a link was made.
func appAutoLinkCode(ctx context.Context, db *store.DB, id int64, insts []appLiveInst) bool {
	reported := map[string]string{} // reported URL -> host
	for _, in := range insts {
		if h, p := repoRef(in.VCSRepo); p != "" {
			reported[in.VCSRepo] = h
		}
	}
	if len(reported) == 0 {
		return false
	}
	if links, _ := db.ServiceCodeLinks(ctx, []int64{id}); len(links) > 0 {
		return false
	}
	conns, err := db.ListDevOpsConnectors(ctx)
	if err != nil {
		return false
	}
	for _, c := range conns {
		host := connectorHost(c)
		rows, err := db.QueryContext(ctx, `SELECT DISTINCT repo FROM sast_results WHERE connector_id = $1 AND repo <> ''`, c.ID)
		if err != nil {
			continue
		}
		var repos []string
		for rows.Next() {
			var r string
			if rows.Scan(&r) == nil {
				repos = append(repos, r)
			}
		}
		rows.Close()
		for raw, h := range reported {
			if host != "" && h != "" && h != host && !strings.HasSuffix(h, "."+host) {
				continue
			}
			for _, repo := range repos {
				if !repoMatches(repo, raw) {
					continue
				}
				if _, err := db.UpsertServiceCodeLink(ctx, store.ServiceCodeLink{ServiceID: id, ConnectorID: c.ID, Repo: repo,
					IsDefault: true, CreatedBy: "reported by the service"}); err == nil {
					appInvalidateCodeIndex()
					return true
				}
			}
		}
	}
	return false
}
