package api

// prevention.go - the prevention policy and the indicator set agents enforce.
//
// The server never writes policy to hosts. It publishes one set of
// indicators (IPs, SHA-256 hashes, domains) with a per-entry expiry, plus a
// mode per indicator type. Agents fetch it through the backend (certificate
// identity, forwarded like the install-key calls), keep it on disk, match
// their own connections, files, processes and DNS answers against it, and
// either report (audit) or act (enforce). Entries expire on the agent, so
// removal works offline.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// Modes for one indicator type.
const (
	PrevOff     = "off"
	PrevAudit   = "audit"   // report matches, change nothing
	PrevEnforce = "enforce" // act on matches
)

// PreventionPolicy is stored as JSON in settings ("prevention.policy").
type PreventionPolicy struct {
	IP     string `json:"ip"`
	Hash   string `json:"hash"`
	Domain string `json:"domain"`
	// EnforceTags, when set, limits enforce to hosts with one of these tags
	// (canary first); other hosts run the same types in audit.
	EnforceTags []string `json:"enforce_tags"`
	// MinConfidence for ThreatFox entries (default 75); Feodo needs 90.
	MinConfidence int `json:"min_confidence"`
	// MaxAgeDays: entries first seen longer ago are not sent (default 90).
	MaxAgeDays int `json:"max_age_days"`
	// Caps per type; over a cap the best entries are kept and the set says
	// it was truncated.
	MaxIPs     int `json:"max_ips"`
	MaxHashes  int `json:"max_hashes"`
	MaxDomains int `json:"max_domains"`
	// HashWatchDirs are extra folders the agent checks for new files (it
	// always checks Downloads, Desktop and temp directories).
	HashWatchDirs []string `json:"hash_watch_dirs"`
	UpdatedBy     string   `json:"updated_by,omitempty"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
}

func defaultPreventionPolicy() PreventionPolicy {
	return PreventionPolicy{IP: PrevAudit, Hash: PrevAudit, Domain: PrevAudit, MinConfidence: 75, MaxAgeDays: 90,
		MaxIPs: 20000, MaxHashes: 200000, MaxDomains: 50000}
}

func (p *PreventionPolicy) normalise() {
	d := defaultPreventionPolicy()
	for _, m := range []*string{&p.IP, &p.Hash, &p.Domain} {
		switch *m {
		case PrevOff, PrevAudit, PrevEnforce:
		default:
			*m = PrevAudit
		}
	}
	if p.MinConfidence < 50 || p.MinConfidence > 100 {
		p.MinConfidence = d.MinConfidence
	}
	if p.MaxAgeDays < 1 || p.MaxAgeDays > 365 {
		p.MaxAgeDays = d.MaxAgeDays
	}
	clampCap := func(v *int, def, hard int) {
		if *v <= 0 {
			*v = def
		}
		if *v > hard {
			*v = hard
		}
	}
	clampCap(&p.MaxIPs, d.MaxIPs, 100000)
	clampCap(&p.MaxHashes, d.MaxHashes, 1000000)
	clampCap(&p.MaxDomains, d.MaxDomains, 200000)
	var tags []string
	for _, t := range p.EnforceTags {
		if t = strings.TrimSpace(t); t != "" && len(t) <= 64 {
			tags = append(tags, t)
		}
	}
	p.EnforceTags = tags
	var dirs []string
	for _, d := range p.HashWatchDirs {
		if d = strings.TrimSpace(d); d != "" && len(d) <= 512 && len(dirs) < 32 {
			dirs = append(dirs, d)
		}
	}
	p.HashWatchDirs = dirs
}

func loadPreventionPolicy(ctx context.Context, db *store.DB) PreventionPolicy {
	p := defaultPreventionPolicy()
	if v, _ := db.GetSetting(ctx, "prevention.policy"); v != "" {
		_ = json.Unmarshal([]byte(v), &p)
	}
	p.normalise()
	return p
}

// PrevEntry is one indicator as the agent receives it.
type PrevEntry struct {
	V     string `json:"v"`
	Until int64  `json:"until"` // unix seconds
	Src   string `json:"src"`
	Conf  int    `json:"conf,omitempty"`
	Name  string `json:"name,omitempty"` // malware family
}

// PrevSet is the published set (the same for every agent; modes differ).
type PrevSet struct {
	Version     string      `json:"version"`
	GeneratedAt time.Time   `json:"generated_at"`
	IPs         []PrevEntry `json:"ips"`
	Hashes      []PrevEntry `json:"hashes"`
	Domains     []PrevEntry `json:"domains"`
	Truncated   []string    `json:"truncated,omitempty"` // types over their cap
	Dropped     int         `json:"dropped_protected"`   // entries refused by the protection rules
}

// Addresses and names never sent for blocking, whatever a feed says:
// resolvers, the big shared platforms, and anything non-public.
var prevProtectedIPs = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true, "1.1.1.1": true, "1.0.0.1": true, "9.9.9.9": true, "149.112.112.112": true,
	"208.67.222.222": true, "208.67.220.220": true, "4.2.2.1": true, "4.2.2.2": true, "94.140.14.14": true,
	"2001:4860:4860::8888": true, "2001:4860:4860::8844": true, "2606:4700:4700::1111": true,
}

var prevProtectedDomains = []string{
	"google.com", "googleapis.com", "gstatic.com", "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
	"live.com", "azure.com", "azureedge.net", "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "cloudfront.net",
	"cloudflare.com", "akamai.net", "akamaiedge.net", "github.com", "githubusercontent.com", "ubuntu.com", "debian.org",
	"redhat.com", "fedoraproject.org", "mozilla.org", "facebook.com", "whatsapp.net", "linkedin.com",
}

func prevPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10 carrier-grade NAT
			return false
		}
		if v4[0] == 0 || v4[0] >= 240 || (v4[0] == 192 && v4[1] == 0 && v4[2] == 2) ||
			(v4[0] == 198 && (v4[1] == 18 || v4[1] == 19 || (v4[1] == 51 && v4[2] == 100))) || (v4[0] == 203 && v4[1] == 0 && v4[2] == 113) {
			return false // reserved and documentation ranges
		}
	}
	return true
}

func protectedDomain(d string) bool {
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	if !strings.Contains(d, ".") {
		return true
	}
	for _, p := range prevProtectedDomains {
		if d == p || strings.HasSuffix(d, "."+p) {
			return true
		}
	}
	return false
}

// buildPrevSet turns candidates into the published set: protection rules,
// one entry per value (longest validity wins), caps.
func buildPrevSet(cands []store.PreventionCandidate, pol PreventionPolicy, now time.Time) PrevSet {
	set := PrevSet{GeneratedAt: now.UTC(), IPs: []PrevEntry{}, Hashes: []PrevEntry{}, Domains: []PrevEntry{}}
	seen := map[string]int{} // type|value -> index
	caps := map[string]int{"ip": pol.MaxIPs, "hash": pol.MaxHashes, "domain": pol.MaxDomains}
	lists := map[string]*[]PrevEntry{"ip": &set.IPs, "hash": &set.Hashes, "domain": &set.Domains}
	truncated := map[string]bool{}
	for _, c := range cands {
		v := strings.ToLower(strings.TrimSpace(c.Value))
		switch c.Type {
		case "ip":
			if !prevPublicIP(v) || prevProtectedIPs[v] {
				set.Dropped++
				continue
			}
			v = net.ParseIP(v).String()
		case "domain":
			v = strings.TrimSuffix(v, ".")
			if protectedDomain(v) {
				set.Dropped++
				continue
			}
		case "hash":
			if _, err := hex.DecodeString(v); err != nil || len(v) != 64 || v == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" { // empty file
				set.Dropped++
				continue
			}
		default:
			continue
		}
		if !c.Until.After(now) {
			continue
		}
		key := c.Type + "|" + v
		list := lists[c.Type]
		if i, ok := seen[key]; ok {
			if u := c.Until.Unix(); u > (*list)[i].Until {
				(*list)[i].Until = u
			}
			continue
		}
		if len(*list) >= caps[c.Type] {
			truncated[c.Type] = true
			continue
		}
		seen[key] = len(*list)
		name := c.Malware
		if len(name) > 80 {
			name = name[:80]
		}
		*list = append(*list, PrevEntry{V: v, Until: c.Until.Unix(), Src: c.Source, Conf: c.Confidence, Name: name})
	}
	for _, t := range []string{"ip", "hash", "domain"} {
		if truncated[t] {
			set.Truncated = append(set.Truncated, t)
		}
	}
	h := sha256.New()
	for _, l := range []*[]PrevEntry{&set.IPs, &set.Hashes, &set.Domains} {
		for _, e := range *l {
			h.Write([]byte(e.V))
			h.Write([]byte{byte(e.Until), byte(e.Until >> 8), byte(e.Until >> 16), byte(e.Until >> 24)})
		}
		h.Write([]byte{0})
	}
	set.Version = hex.EncodeToString(h.Sum(nil))[:16]
	return set
}

// prevSetCache holds the built set; rebuilt when older than prevRebuild or
// when the policy changes.
var prevSetCache struct {
	sync.Mutex
	set   *PrevSet
	body  []byte
	built time.Time
	pol   PreventionPolicy
}

const prevRebuild = 10 * time.Minute

func currentPrevSet(ctx context.Context, db *store.DB) (*PrevSet, []byte, PreventionPolicy, error) {
	pol := loadPreventionPolicy(ctx, db)
	prevSetCache.Lock()
	defer prevSetCache.Unlock()
	polJSON, _ := json.Marshal(pol.withoutAudit())
	oldJSON, _ := json.Marshal(prevSetCache.pol.withoutAudit())
	if prevSetCache.set != nil && time.Since(prevSetCache.built) < prevRebuild && string(polJSON) == string(oldJSON) {
		return prevSetCache.set, prevSetCache.body, pol, nil
	}
	cands, err := db.PreventionCandidates(ctx, pol.MinConfidence, time.Duration(pol.MaxAgeDays)*24*time.Hour)
	if err != nil {
		return nil, nil, pol, err
	}
	set := buildPrevSet(cands, pol, time.Now())
	body, _ := json.Marshal(set)
	prevSetCache.set, prevSetCache.body, prevSetCache.built, prevSetCache.pol = &set, body, time.Now(), pol
	return &set, body, pol, nil
}

func (p PreventionPolicy) withoutAudit() PreventionPolicy {
	p.UpdatedAt, p.UpdatedBy = "", ""
	return p
}

func invalidatePrevSet() {
	prevSetCache.Lock()
	prevSetCache.set = nil
	prevSetCache.Unlock()
}

// modesFor resolves the modes one host runs: enforce is limited to hosts
// carrying an enforce tag when the policy names any.
func modesFor(pol PreventionPolicy, hostTags []string) map[string]string {
	canEnforce := len(pol.EnforceTags) == 0
	for _, t := range hostTags {
		for _, want := range pol.EnforceTags {
			if strings.EqualFold(t, want) {
				canEnforce = true
			}
		}
	}
	m := map[string]string{"ip": pol.IP, "hash": pol.Hash, "domain": pol.Domain}
	for k, v := range m {
		if v == PrevEnforce && !canEnforce {
			m[k] = PrevAudit
		}
	}
	return m
}

// GET /api/v1/agent/prevention (agent certificate, forwarded by the backend)
// The agent sends ?have=<version>; an unchanged set answers with modes only.
func handleAgentPrevention(db *store.DB, ta *tunnelAuth, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := ta.authenticate(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}
		set, body, pol, err := currentPrevSet(r.Context(), db)
		if err != nil {
			logger.Error("prevention: build set", "err", err)
			writeJSON(w, 500, map[string]string{"error": "prevention set unavailable"})
			return
		}
		var tags []string
		if a, err := db.GetAgent(r.Context(), caller.agentID); err == nil && a != nil {
			tags = hostTags(r.Context(), db, a.Hostname)
		}
		resp := map[string]any{
			"version": set.Version, "modes": modesFor(pol, tags), "hash_watch_dirs": pol.HashWatchDirs,
			"refresh_seconds": 900,
		}
		if r.URL.Query().Get("have") != set.Version {
			resp["set"] = json.RawMessage(body)
		}
		writeJSON(w, 200, resp)
	}
}

func hostTags(ctx context.Context, db *store.DB, host string) []string {
	metas, err := db.ListHostMeta(ctx)
	if err != nil {
		return nil
	}
	for _, m := range metas {
		if strings.EqualFold(m.Host, host) {
			return m.Tags
		}
	}
	return nil
}

// GET /api/v1/prevention (policy and what the set holds now)
func handleGetPrevention(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		set, _, pol, err := currentPrevSet(r.Context(), db)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "prevention set unavailable"})
			return
		}
		bySrc := map[string]map[string]int{}
		for t, l := range map[string][]PrevEntry{"ip": set.IPs, "hash": set.Hashes, "domain": set.Domains} {
			bySrc[t] = map[string]int{}
			for _, e := range l {
				bySrc[t][e.Src]++
			}
		}
		writeJSON(w, 200, map[string]any{
			"policy": pol,
			"set": map[string]any{
				"version": set.Version, "generated_at": set.GeneratedAt,
				"ips": len(set.IPs), "hashes": len(set.Hashes), "domains": len(set.Domains),
				"by_source": bySrc, "truncated": set.Truncated, "dropped_protected": set.Dropped,
			},
		})
	}
}

// PUT /api/v1/prevention (admin)
func handlePutPrevention(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p PreventionPolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&p); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid policy"})
			return
		}
		p.normalise()
		if c := auth.GetClaims(r); c != nil {
			p.UpdatedBy = c.Username
		}
		p.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		b, _ := json.Marshal(p)
		if err := db.SetSetting(r.Context(), "prevention.policy", string(b)); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to save"})
			return
		}
		invalidatePrevSet()
		db.WriteAudit(r.Context(), p.UpdatedBy, "prevention.policy.update", "prevention", string(b), clientIP(r))
		writeJSON(w, 200, p)
	}
}
