package api

// otx_score.go - per-pulse confidence for OTX indicators (FP-reduction A3).
// All weights live here so they can be tuned against fleet-replay output.

import (
	"strings"
	"time"
)

const (
	otxScoreBase         = 25
	otxScoreAdversary    = 25
	otxScoreFamilies     = 20
	otxScoreAttack       = 10
	otxScoreReferences   = 5
	otxPenaltyBigPulse   = -20
	otxPenaltyHashOnly   = -10
	otxPenaltyStale      = -10
	otxBigPulseThreshold = 500
	otxStaleAfter        = 180 * 24 * time.Hour
	otxScoreMin          = 5
	otxScoreMax          = 85
	otxDefaultTTL        = 90 * 24 * time.Hour
)

type otxPulseMeta struct {
	Adversary   string
	HasFamilies bool
	HasAttack   bool
	HasRefs     bool
	HasTags     bool
	Size        int // indicator count
	AllHashes   bool
	Modified    time.Time // zero = unknown
}

// otxPulseScore returns the confidence (5..85) for indicators of one pulse.
func otxPulseScore(m otxPulseMeta, now time.Time) int {
	s := otxScoreBase
	if strings.TrimSpace(m.Adversary) != "" {
		s += otxScoreAdversary
	}
	if m.HasFamilies {
		s += otxScoreFamilies
	}
	if m.HasAttack {
		s += otxScoreAttack
	}
	if m.HasRefs {
		s += otxScoreReferences
	}
	if m.Size > otxBigPulseThreshold {
		s += otxPenaltyBigPulse
	}
	if m.AllHashes && !m.HasTags && strings.TrimSpace(m.Adversary) == "" && !m.HasFamilies {
		s += otxPenaltyHashOnly
	}
	if !m.Modified.IsZero() && now.Sub(m.Modified) > otxStaleAfter {
		s += otxPenaltyStale
	}
	if s < otxScoreMin {
		s = otxScoreMin
	}
	if s > otxScoreMax {
		s = otxScoreMax
	}
	return s
}

// nonEmptyJSON reports whether a raw JSON value is present and not null/[]/"".
func nonEmptyJSON(b []byte) bool {
	t := strings.TrimSpace(string(b))
	return t != "" && t != "null" && t != "[]" && t != `""` && t != "{}"
}

// iocIngestOK drops indicators that can only produce noise: non-public IPs and
// very popular domains (FP-reduction A4).
func iocIngestOK(iocType, value string) bool {
	switch iocType {
	case "ip":
		return publicIP(value)
	case "domain":
		return !isPopularDomain(value)
	}
	return true
}

// popularDomains is a small embedded list of domains that must never be IOCs.
// TODO: replace with a Tranco top-10k list (see spec open question 3).
var popularDomains = map[string]bool{
	"google.com": true, "googleapis.com": true, "gstatic.com": true, "googleusercontent.com": true,
	"microsoft.com": true, "windows.com": true, "windowsupdate.com": true, "office.com": true,
	"live.com": true, "azure.com": true, "azureedge.net": true, "msftconnecttest.com": true,
	"apple.com": true, "icloud.com": true, "amazon.com": true, "amazonaws.com": true,
	"cloudfront.net": true, "github.com": true, "githubusercontent.com": true, "gitlab.com": true,
	"cloudflare.com": true, "akamai.net": true, "akamaiedge.net": true, "fastly.net": true,
	"facebook.com": true, "instagram.com": true, "twitter.com": true, "x.com": true,
	"linkedin.com": true, "youtube.com": true, "wikipedia.org": true, "mozilla.org": true,
	"ubuntu.com": true, "debian.org": true, "canonical.com": true, "redhat.com": true,
	"docker.com": true, "docker.io": true, "npmjs.com": true, "pypi.org": true,
	"python.org": true, "golang.org": true, "go.dev": true, "oracle.com": true,
	"adobe.com": true, "dropbox.com": true, "slack.com": true, "zoom.us": true,
	"digicert.com": true, "letsencrypt.org": true, "sectigo.com": true, "verisign.com": true,
	"yahoo.com": true, "bing.com": true, "baidu.com": true, "paypal.com": true,
}

func isPopularDomain(d string) bool {
	r := registrableDomain(d)
	return r == "" || popularDomains[r]
}
