package api

// ioc_gate.go - known-good gate for hash IOC matches (FP-reduction A2) and
// the suppression IDs used for IOC and Sigma alerts (A6).

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// systemBinPrefixes are directories whose binaries come from the OS package
// manager. A hash IOC hit on one of these is never alerted above Medium.
var systemBinPrefixes = []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/lib/"}

const (
	iocSevInfo   = 1
	iocSevMedium = 3
)

type iocRawFlags struct {
	PkgVerified   *bool  `json:"pkg_verified"`
	SignedTrusted *bool  `json:"signed_trusted"`
	Exe           string `json:"exe"`
}

// iocKnownGoodAdjust lowers the severity of a hash IOC hit when the event says
// the binary is package-verified / trusted-signed, or when it runs from a
// system directory and pkg_verified is unknown. It downgrades and tags; it
// never drops the match. Non-hash IOCs and events without the new agent
// fields are returned unchanged (absence of pkg_verified means "unknown").
func iocKnownGoodAdjust(ev store.Event, ioc store.IOCIndicator) store.IOCIndicator {
	if ioc.IOCType != "hash" {
		return ioc
	}
	var f iocRawFlags
	if len(ev.Raw) > 0 {
		_ = json.Unmarshal(ev.Raw, &f) // partial decode is fine
	}
	tag := func(t string) string {
		if ioc.Tags == "" {
			return t
		}
		return ioc.Tags + "," + t
	}
	if (f.PkgVerified != nil && *f.PkgVerified) || (f.SignedTrusted != nil && *f.SignedTrusted) {
		ioc.Severity = iocSevInfo
		ioc.Tags = tag("ioc:known_good")
		return ioc
	}
	if f.PkgVerified != nil && !*f.PkgVerified {
		// Explicitly NOT package-verified: a modified or unowned binary in a
		// system directory is exactly what an IOC hit should surface.
		return ioc
	}
	path := strings.ToLower(f.Exe)
	if path == "" && ev.ImagePath != nil {
		path = strings.ToLower(*ev.ImagePath)
	}
	for _, p := range systemBinPrefixes {
		if strings.HasPrefix(path, p) {
			if ioc.Severity > iocSevMedium {
				ioc.Severity = iocSevMedium
				ioc.Tags = tag("ioc:system_path")
			}
			break
		}
	}
	return ioc
}

// iocSuppressID is the rule ID an IOC alert is suppressed under,
// e.g. "IOC:otx:hash".
func iocSuppressID(ioc store.IOCIndicator) string {
	return "IOC:" + strings.ToLower(ioc.Source) + ":" + strings.ToLower(ioc.IOCType)
}

// sigmaSuppressID is the rule ID a Sigma alert is suppressed under.
func sigmaSuppressID(ruleID string) string { return "SIGMA:" + ruleID }

// ── fleet prevalence (A2 rule 2) ─────────────────────────────────────────────

const (
	iocPrevalentMinAge    = 7 * 24 * time.Hour
	iocPrevalenceCacheTTL = 10 * time.Minute
)

// iocApplyPrevalence downgrades a hash IOC one severity step when the hash has
// run on at least minHosts hosts and was first seen at least 7 days ago: a
// binary that has been all over the fleet for a week without incident is
// unlikely to be fresh malware. With a small fleet this rarely triggers; the
// package-verified tag is the primary fix.
func iocApplyPrevalence(ioc store.IOCIndicator, hosts int, first time.Time, minHosts int, now time.Time) store.IOCIndicator {
	if ioc.IOCType != "hash" || ioc.Severity <= iocSevInfo || minHosts <= 0 || hosts < minHosts ||
		first.IsZero() || now.Sub(first) < iocPrevalentMinAge {
		return ioc
	}
	ioc.Severity--
	if ioc.Tags == "" {
		ioc.Tags = "ioc:prevalent"
	} else {
		ioc.Tags += ",ioc:prevalent"
	}
	return ioc
}

func settingInt(v string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
		return n
	}
	return def
}

type prevCacheEntry struct {
	hosts int
	first time.Time
	at    time.Time
}

var (
	prevCacheMu sync.Mutex
	prevCache   = map[string]prevCacheEntry{}
)

// hashPrevalence returns (hosts, first seen) for a hash, cached for 10 minutes.
func (e *DetectionEngine) hashPrevalence(ctx context.Context, hash string) (int, time.Time, bool) {
	key := "hash:" + strings.ToLower(hash)
	prevCacheMu.Lock()
	if c, ok := prevCache[key]; ok && time.Since(c.at) < iocPrevalenceCacheTTL {
		prevCacheMu.Unlock()
		return c.hosts, c.first, true
	}
	if len(prevCache) > 5000 {
		prevCache = map[string]prevCacheEntry{}
	}
	prevCacheMu.Unlock()
	info, err := e.db.GetPrevalence(ctx, key)
	if err != nil || info == nil {
		return 0, time.Time{}, false
	}
	var first time.Time
	if info.FirstSeen != nil {
		first = *info.FirstSeen
	}
	prevCacheMu.Lock()
	prevCache[key] = prevCacheEntry{hosts: info.HostCount, first: first, at: time.Now()}
	prevCacheMu.Unlock()
	return info.HostCount, first, true
}
