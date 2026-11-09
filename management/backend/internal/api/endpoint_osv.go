package api

// F-21: endpoint vulnerability matching against OSV distro advisories (Ubuntu,
// Debian, Alpine), replacing keyword search for the package list the agent
// already reports. OSV evaluates version ranges, so results carry a real
// "fixed in" version. Limitation: dpkg reports binary package names while
// OSV Debian/Ubuntu records are keyed by source package, so some library
// packages (e.g. libssl3 -> openssl) are not matched; results are therefore
// a lower bound, not a complete list.

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"obsidianwatch/management/internal/store"
)

var (
	ubuntuRe = regexp.MustCompile(`(?i)ubuntu\s+(\d+\.\d+)`)
	debianRe = regexp.MustCompile(`(?i)debian[^0-9]*(\d+)`)
	alpineRe = regexp.MustCompile(`(?i)alpine[^0-9]*v?(\d+\.\d+)`)
)

// osvEcosystemForOS maps /etc/os-release PRETTY_NAME to an OSV ecosystem.
func osvEcosystemForOS(osRelease string) string {
	if m := ubuntuRe.FindStringSubmatch(osRelease); m != nil {
		return "Ubuntu:" + m[1]
	}
	if m := debianRe.FindStringSubmatch(osRelease); m != nil {
		return "Debian:" + m[1]
	}
	if m := alpineRe.FindStringSubmatch(osRelease); m != nil {
		return "Alpine:v" + m[1]
	}
	return ""
}

// endpointPkgs extracts matchable packages from a vulnerability.scan payload.
func endpointPkgs(raw json.RawMessage) (eco string, pkgs []scaPkg) {
	var m struct {
		System struct {
			OSRelease string `json:"os_release"`
		} `json:"system"`
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return "", nil
	}
	eco = osvEcosystemForOS(m.System.OSRelease)
	if eco == "" {
		return "", nil
	}
	for _, p := range m.Packages {
		if p.Name != "" && p.Version != "" {
			pkgs = append(pkgs, scaPkg{Ecosystem: eco, Name: p.Name, Version: p.Version, File: "installed packages"})
		}
	}
	return eco, pkgs
}

func handleEndpointOSV(db, backendDB *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		if host == "" {
			writeJSONError(w, http.StatusBadRequest, "missing host")
			return
		}
		f := store.EventFilter{HostExact: host, EventType: "vulnerability.scan", Limit: 1}
		events, _, err := db.QueryEvents(r.Context(), f)
		if (err != nil || len(events) == 0) && backendDB != nil {
			events, _, err = backendDB.QueryEvents(r.Context(), f)
		}
		if err != nil || len(events) == 0 {
			writeJSONError(w, http.StatusNotFound, "no vulnerability scan found for this host")
			return
		}
		eco, pkgs := endpointPkgs(events[0].Raw)
		if eco == "" {
			writeJSONError(w, http.StatusUnprocessableEntity, "unsupported OS for OSV matching (Ubuntu, Debian and Alpine are supported)")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		findings, err := scaFindings(ctx, host, pkgs)
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, "OSV lookup failed: "+err.Error())
			return
		}
		counts := map[string]int{}
		for _, f := range findings {
			counts[f.Severity]++
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"host": host, "ecosystem": eco, "packages_checked": len(pkgs),
			"findings": findings, "by_severity": counts, "scanned_at": time.Now().UTC(),
			"note": "Matched by source-package name; some binary-only library packages may not match.",
		})
	}
}
