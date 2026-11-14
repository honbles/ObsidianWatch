package api

// graph_join.go — Alert Graph: file -> process joins and the campaign
// (multi-alert) layer. A file written by one process and later executed by
// another is joined only on exact path (evidence "path") or matching hash
// (evidence "hash"), never on time proximity. This is what connects a browser
// download, a USB drop, an email attachment or a persisted payload to the
// process that finally ran it.

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type gFileLink struct {
	writer, exec string
	path, host   string
	hashMatch    bool
	t            time.Time
}

const (
	graphMaxOrigins   = 5
	graphMaxExecuted  = 10
	graphMaxJoinPaths = 40
)

var driveLetterRe = regexp.MustCompile(`^[d-z]:/`)

// userWritableImage reports paths where a program is typically dropped rather
// than installed: user profiles, temp, downloads, mounts and non-system drives
// (USB and network shares). System install directories are skipped so the join
// queries stay small and meaningful.
func userWritableImage(p string) bool {
	l := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	if driveLetterRe.MatchString(l) {
		return true
	}
	for _, s := range []string{"/users/", "/home/", "/tmp/", "/dev/shm/", "/var/tmp/", "/programdata/", "/appdata/",
		"/downloads/", "/mnt/", "/media/", "/volumes/", "/windows/temp/", "/root/"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// hashEq compares two hash fields such as "SHA256=ab..,MD5=cd.." or a bare hex
// digest, ignoring case and algorithm prefix.
func hashEq(a, b string) bool {
	norm := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, part := range strings.Split(s, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if i := strings.Index(part, "="); i >= 0 {
				part = part[i+1:]
			}
			if len(part) >= 32 {
				m[part] = true
			}
		}
		return m
	}
	ma, mb := norm(a), norm(b)
	for h := range ma {
		if mb[h] {
			return true
		}
	}
	return false
}

// downloadURL extracts the origin URL from a Sysmon FileCreateStreamHash
// (Mark-of-the-Web) event: "[ZoneTransfer] ZoneId=3 ReferrerUrl=.. HostUrl=..".
func downloadURL(ev store.Event) string {
	if ev.EventType != "file" || len(ev.Raw) == 0 || !strings.Contains(string(ev.Raw), "HostUrl") {
		return ""
	}
	s := string(ev.Raw)
	// the Contents value is JSON-escaped (\r\n); read HostUrl up to the next escape or quote
	i := strings.Index(s, "HostUrl=")
	if i < 0 {
		return ""
	}
	rest := s[i+len("HostUrl="):]
	end := len(rest)
	for _, sep := range []string{`\r`, `\n`, `"`} {
		if j := strings.Index(rest, sep); j >= 0 && j < end {
			end = j
		}
	}
	u := strings.TrimSpace(rest[:end])
	if pu, err := url.Parse(u); err != nil || pu.Host == "" {
		return ""
	}
	return graphTrunc(u, 300)
}

// urlKey normalises a path to its file (dropping an NTFS alternate-stream
// suffix such as ":Zone.Identifier") for the download-URL map.
func urlKey(p string) string {
	l := store.LowerCap512(p)
	if i := strings.LastIndex(l, ":"); i > 1 {
		l = l[:i]
	}
	return l
}

func (b *gBuilder) keySet() map[string]bool {
	m := make(map[string]bool, len(b.procs))
	for k := range b.procs {
		m[k] = true
	}
	return m
}

func (b *gBuilder) joinFiles() error {
	upFrom := b.alertT.AddDate(0, 0, -30)

	// Backward: who wrote the files that the lineage runs?
	cand := map[string][]string{}
	for k, p := range b.procs {
		if p.rolePref != "" || p.image == "" || !userWritableImage(p.image) {
			continue
		}
		cand[store.LowerCap512(p.image)] = append(cand[store.LowerCap512(p.image)], k)
	}
	if len(cand) > 0 {
		paths := make([]string, 0, len(cand))
		for p := range cand {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		if len(paths) > graphMaxJoinPaths {
			paths = paths[:graphMaxJoinPaths]
		}
		evs, err := b.query(func() ([]store.Event, error) {
			return b.src.EventsByFilePaths(b.ctx, b.agent, paths, upFrom, b.to, 2000)
		}, 2000)
		if err != nil {
			return err
		}
		best := map[string]store.Event{}
		for _, ev := range evs {
			if ev.ProcessGUID == "" {
				continue
			}
			pk := store.LowerCap512(gs(ev.FilePath))
			for _, ek := range cand[pk] {
				ep := b.procs[ek]
				if ep == nil || ep.key == ev.ProcessGUID {
					continue
				}
				if !ep.first.IsZero() && ev.Time.After(ep.first) {
					continue // written after it started: not its origin
				}
				id := pk + "|" + ek
				if cur, ok := best[id]; !ok || ev.Time.After(cur.Time) {
					best[id] = ev
				}
			}
			if u := downloadURL(ev); u != "" {
				b.urls[urlKey(gs(ev.FilePath))] = u
			}
		}
		ids := make([]string, 0, len(best))
		for id := range best {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var newWriters []string
		type pending struct {
			link gFileLink
		}
		var pend []pending
		for _, id := range ids {
			ev := best[id]
			ek := id[strings.LastIndex(id, "|")+1:]
			ep := b.procs[ek]
			if b.procs[ev.ProcessGUID] == nil {
				if len(newWriters) >= graphMaxOrigins {
					continue
				}
				newWriters = append(newWriters, ev.ProcessGUID)
			}
			pend = append(pend, pending{gFileLink{writer: ev.ProcessGUID, exec: ek, path: gs(ev.FilePath), host: ev.Host,
				hashMatch: hashEq(gs(ev.FileHash), ep.hash), t: ev.Time}})
		}
		newWriters = uniq(newWriters)
		if len(newWriters) > 0 {
			evs, err := b.query(func() ([]store.Event, error) {
				return b.src.EventsByProcessGUIDs(b.ctx, b.agent, newWriters, upFrom, b.to, graphEventLimit)
			}, graphEventLimit)
			if err != nil {
				return err
			}
			b.ingest(evs)
			var made []string
			for _, w := range newWriters {
				if p := b.procs[w]; p != nil && !p.seed && p.rolePref == "" {
					p.rolePref = "origin"
					made = append(made, w)
				}
			}
			if err := b.walkUp(made, 3); err != nil {
				return err
			}
		}
		for _, pd := range pend {
			if b.procs[pd.link.writer] != nil {
				b.addLink(pd.link)
			}
		}
	}

	// Forward: who ran the files the lineage wrote?
	type wfile struct {
		writer string
		ev     store.Event
	}
	written := map[string]wfile{}
	for k, p := range b.procs {
		if p.rolePref == "executed" {
			continue
		}
		for _, a := range p.arts {
			if (a.EventType != "file" && a.EventType != "fim") || gs(a.FilePath) == "" || !userWritableImage(gs(a.FilePath)) {
				continue
			}
			pk := store.LowerCap512(gs(a.FilePath))
			if cur, ok := written[pk]; !ok || a.Time.After(cur.ev.Time) {
				written[pk] = wfile{k, a}
			}
			if u := downloadURL(a); u != "" {
				b.urls[urlKey(gs(a.FilePath))] = u
			}
		}
	}
	if len(written) == 0 {
		return nil
	}
	paths := make([]string, 0, len(written))
	for p := range written {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) > graphMaxJoinPaths {
		paths = paths[:graphMaxJoinPaths]
	}
	evs, err := b.query(func() ([]store.Event, error) {
		return b.src.EventsByImagePaths(b.ctx, b.agent, paths, b.from, b.to, 1000)
	}, 1000)
	if err != nil {
		return err
	}
	before := b.keySet()
	var newExec []string
	for _, ev := range evs {
		if !isProcStartEvent(ev) || ev.ProcessGUID == "" {
			continue
		}
		pk := store.LowerCap512(gs(ev.ImagePath))
		w, ok := written[pk]
		if !ok || ev.Time.Before(w.ev.Time) || ev.ProcessGUID == w.writer {
			continue
		}
		if b.procs[ev.ProcessGUID] == nil {
			if len(newExec) >= graphMaxExecuted || len(b.procs) >= graphMaxProcs {
				continue
			}
			b.ingest([]store.Event{ev})
			if p := b.procs[ev.ProcessGUID]; p != nil {
				p.rolePref = "executed"
				newExec = append(newExec, ev.ProcessGUID)
			}
		}
		if ep := b.procs[ev.ProcessGUID]; ep != nil {
			b.addLink(gFileLink{writer: w.writer, exec: ev.ProcessGUID, path: gs(w.ev.FilePath), host: w.ev.Host,
				hashMatch: hashEq(gs(w.ev.FileHash), gs(ev.FileHash)), t: ev.Time})
		}
	}
	if len(newExec) > 0 {
		if err := b.walkDown(newExec); err != nil {
			return err
		}
		var added []string
		for k := range b.procs {
			if !before[k] {
				added = append(added, k)
			}
		}
		sort.Strings(added)
		if err := b.fetchArts(added); err != nil {
			return err
		}
	}
	return nil
}

func (b *gBuilder) addLink(l gFileLink) {
	for _, x := range b.links {
		if x.writer == l.writer && x.exec == l.exec && strings.EqualFold(x.path, l.path) {
			return
		}
	}
	b.links = append(b.links, l)
}

func (l gFileLink) fileID() string { return "file:" + l.host + ":" + l.path }

// ---------------------------------------------------------------------------
// Campaign: alerts on the graph, in time order, plus alerts that share
// explicit evidence (same IP, domain or file) with it.
// ---------------------------------------------------------------------------

type AGRelated struct {
	Alert    store.AlertBrief `json:"alert"`
	Via      string           `json:"via"`
	SameHost bool             `json:"same_host"`
}

type AGCampaign struct {
	Alerts  []store.AlertBrief `json:"alerts"`
	Related []AGRelated        `json:"related"`
}

func (b *gBuilder) enrichAlerts(g *AlertGraph) {
	onGraph := map[int64]bool{}
	if b.in.Alert.ID != 0 {
		onGraph[b.in.Alert.ID] = true
	}
	for _, n := range g.Nodes {
		for _, id := range n.Alerts {
			onGraph[id] = true
		}
	}
	via := map[int64]string{}
	collect := func(kind string, keys map[string]string) {
		if len(keys) == 0 {
			return
		}
		ks := make([]string, 0, len(keys))
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		b.queries++
		m, err := b.src.AlertEntityMap(b.ctx, kind, ks, 5)
		if err != nil {
			return
		}
		for _, k := range ks {
			for _, id := range m[k] {
				if !onGraph[id] {
					if _, ok := via[id]; !ok {
						via[id] = keys[k]
					}
				}
			}
		}
	}
	ipK, domK, fileK := map[string]string{}, map[string]string{}, map[string]string{}
	for _, n := range g.Nodes {
		switch n.Type {
		case "ip":
			ipK[strings.ToLower(n.Label)] = "same IP " + n.Label
		case "domain":
			domK[strings.ToLower(n.Label)] = "same domain " + n.Label
		case "file":
			if rest := strings.TrimPrefix(n.ID, "file:"); rest != n.ID {
				if i := strings.Index(rest, ":"); i > 0 {
					fileK[rest[:i]+"|"+strings.ToLower(rest[i+1:])] = "same file " + n.Label
				}
			}
		}
	}
	collect(EntityIP, ipK)
	collect(EntityDomain, domK)
	collect(EntityFile, fileK)

	all := make([]int64, 0, len(onGraph)+len(via))
	for id := range onGraph {
		all = append(all, id)
	}
	relIDs := make([]int64, 0, len(via))
	for id := range via {
		relIDs = append(relIDs, id)
	}
	sort.Slice(relIDs, func(i, j int) bool { return relIDs[i] > relIDs[j] })
	if len(relIDs) > 15 {
		relIDs = relIDs[:15]
	}
	all = append(all, relIDs...)
	b.queries++
	briefs, err := b.src.AlertBriefs(b.ctx, all)
	if err != nil {
		return
	}
	for i := range g.Nodes {
		for _, id := range g.Nodes[i].Alerts {
			if br, ok := briefs[id]; ok {
				g.Nodes[i].AlertInfo = append(g.Nodes[i].AlertInfo, br)
			}
		}
	}
	for id := range onGraph {
		if br, ok := briefs[id]; ok {
			g.Campaign.Alerts = append(g.Campaign.Alerts, br)
		}
	}
	sort.Slice(g.Campaign.Alerts, func(i, j int) bool {
		a, c := g.Campaign.Alerts[i], g.Campaign.Alerts[j]
		if !a.CreatedAt.Equal(c.CreatedAt) {
			return a.CreatedAt.Before(c.CreatedAt)
		}
		return a.ID < c.ID
	})
	for _, id := range relIDs {
		if br, ok := briefs[id]; ok {
			g.Campaign.Related = append(g.Campaign.Related, AGRelated{Alert: br, Via: via[id], SameHost: br.Host == b.in.Alert.Host})
		}
	}
}
