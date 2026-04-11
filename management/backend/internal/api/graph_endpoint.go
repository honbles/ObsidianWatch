package api

// graph_endpoint.go — Endpoint Threat Graph builder.
//
// Builds a rich force-directed graph from all events for a given host.
// Returns nodes and edges that the frontend renders with D3.
//
// Node types: host, process, dns, ip, file, registry, logon
// Edge types: spawned, queried, connected, wrote, read, deleted, modified, auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Graph filtering rules ─────────────────────────────────────────────────────
//
// These are principle-based rules, not application-specific hardcoding.
// They apply to any process on any OS.

// wellKnownShellPorts are ports commonly used for reverse shells and C2.
// Any outbound connection to these ports creates an explicit IP node in the graph
// regardless of severity, because they are almost never legitimate.
var wellKnownShellPorts = map[int]bool{
	4444: true, // Metasploit default
	1337: true, // Leet/hacker port, common in CTFs and malware
	31337: true, // Elite/back orifice
	9001: true,  // Tor, also common in malware
	6666: true,  // IRC, used by botnets
	6667: true,  // IRC, used by botnets
	6668: true,  // IRC
	6669: true,  // IRC
}

// ── Graph types ──────────────────────────────────────────────────────────────

type GraphNode struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`        // process, dns, ip, file, registry, logon, host
	Label       string                 `json:"label"`
	Severity    int                    `json:"severity"`
	EventCount  int                    `json:"event_count"`
	Meta        map[string]interface{} `json:"meta"`
	Suspicious  bool                   `json:"suspicious"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
}

type GraphEdge struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	Target    string    `json:"target"`
	Type      string    `json:"type"`   // spawned, queried, connected, wrote, deleted, modified, executed
	Count     int       `json:"count"`
	Severity  int       `json:"severity"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type EndpointGraph struct {
	Nodes    []GraphNode `json:"nodes"`
	Edges    []GraphEdge `json:"edges"`
	Meta     struct {
		Host       string    `json:"host"`
		Since      time.Time `json:"since"`
		EventCount int       `json:"event_count"`
		OS         string    `json:"os"`
		AgentID    string    `json:"agent_id"`
	} `json:"meta"`
}

// agentInfo holds basic agent metadata for the network graph
type agentInfo struct {
	hostname string
	lastIP   string
	os       string
}

// ── Graph builder ─────────────────────────────────────────────────────────────

type graphBuilder struct {
	nodes    map[string]*GraphNode
	edges    map[string]*GraphEdge
	pidProc  map[int]*GraphNode  // pid → process node
	pidName  map[int]string      // pid → name (for enrichment)
	host     string
	os       string
	agentID  string
}

func newGraphBuilder(host string) *graphBuilder {
	return &graphBuilder{
		nodes:   make(map[string]*GraphNode),
		edges:   make(map[string]*GraphEdge),
		pidProc: make(map[int]*GraphNode),
		pidName: make(map[int]string),
		host:    host,
	}
}

func (g *graphBuilder) node(id, typ, label string, sev int) *GraphNode {
	if n, ok := g.nodes[id]; ok {
		n.EventCount++
		if sev > n.Severity {
			n.Severity = sev
		}
		return n
	}
	n := &GraphNode{
		ID:         id,
		Type:       typ,
		Label:      label,
		Severity:   sev,
		EventCount: 1,
		Meta:       make(map[string]interface{}),
	}
	if typ == "process" {
		n.Meta["total_connections"] = 0
	}
	g.nodes[id] = n
	return n
}

// nodeAt updates node timestamps from actual event time
func (g *graphBuilder) nodeAt(n *GraphNode, t time.Time) {
	if n.FirstSeen.IsZero() || t.Before(n.FirstSeen) {
		n.FirstSeen = t
	}
	if t.After(n.LastSeen) {
		n.LastSeen = t
	}
}

func (g *graphBuilder) edge(srcID, dstID, typ string, sev int) {
	g.edgeAt(srcID, dstID, typ, sev, time.Time{})
}

func (g *graphBuilder) edgeAt(srcID, dstID, typ string, sev int, t time.Time) {
	id := fmt.Sprintf("%s→%s[%s]", srcID, dstID, typ)
	if e, ok := g.edges[id]; ok {
		e.Count++
		if sev > e.Severity {
			e.Severity = sev
		}
		if !t.IsZero() {
			if e.FirstSeen.IsZero() || t.Before(e.FirstSeen) {
				e.FirstSeen = t
			}
			if t.After(e.LastSeen) {
				e.LastSeen = t
			}
		}
		return
	}
	e := &GraphEdge{
		ID:       id,
		Source:   srcID,
		Target:   dstID,
		Type:     typ,
		Count:    1,
		Severity: sev,
	}
	if !t.IsZero() {
		e.FirstSeen = t
		e.LastSeen  = t
	}
	g.edges[id] = e
}

func (g *graphBuilder) processEvents(events []store.Event) {
	// First pass: build PID→name cache from all process events
	for _, ev := range events {
		if ev.ProcessName != nil && ev.PID != nil && *ev.PID > 0 {
			g.pidName[*ev.PID] = *ev.ProcessName
		}
		if ev.OS != "" {
			g.os = ev.OS
		}
		if ev.AgentID != "" {
			g.agentID = ev.AgentID
		}
	}

	// Second pass: build graph
	for _, ev := range events {
		switch ev.EventType {
		case "process":
			g.handleProcess(ev)
		case "network":
			g.handleNetwork(ev)
		case "dns":
			g.handleDNS(ev)
		case "file":
			g.handleFile(ev)
		case "registry":
			g.handleRegistry(ev)
		case "logon":
			g.handleLogon(ev)
		}
	}

	// Third pass: time-proximity matching for file/registry events without PID
	g.proximityMatch(events)
}

func (g *graphBuilder) handleProcess(ev store.Event) {
	if ev.ProcessName == nil || *ev.ProcessName == "" {
		return
	}

	pid := 0
	if ev.PID != nil {
		pid = *ev.PID
	}
	ppid := 0
	if ev.PPID != nil {
		ppid = *ev.PPID
	}

	name := *ev.ProcessName
	// Key by name only — all instances of chrome.exe become one node
	nodeID := fmt.Sprintf("proc-%s", strings.ToLower(name))

	n := g.node(nodeID, "process", name, int(ev.Severity))
	n.Meta["pid"] = pid
	n.Meta["ppid"] = ppid
	if ev.CommandLine != nil && *ev.CommandLine != "" {
		if _, ok := n.Meta["cmdlines"]; !ok {
			n.Meta["cmdlines"] = []string{}
		}
		cmds := n.Meta["cmdlines"].([]string)
		// Deduplicate
		found := false
		for _, c := range cmds {
			if c == *ev.CommandLine {
				found = true
				break
			}
		}
		if !found && len(cmds) < 20 {
			n.Meta["cmdlines"] = append(cmds, *ev.CommandLine)
		}
	}
	if ev.ImagePath != nil && *ev.ImagePath != "" {
		if _, exists := n.Meta["image_path"]; !exists {
			n.Meta["image_path"] = *ev.ImagePath
		}
	}
	if ev.UserName != nil && n.Meta["user"] == nil {
		n.Meta["user"] = *ev.UserName
	}
	g.nodeAt(n, ev.Time)
	// Store event IDs for alert correlation
	if ev.ID != "" {
		ids := append(nodeEventIDs(n), ev.ID)
		n.Meta["event_ids"] = ids
	}

	// Track pid→node mapping
	if pid > 0 {
		g.pidProc[pid] = n
	}

	// Parent→child spawn edge
	if ppid > 0 {
		if parentName, ok := g.pidName[ppid]; ok {
			parentID := fmt.Sprintf("proc-%s-%d", strings.ToLower(parentName), ppid)
			if _, exists := g.nodes[parentID]; exists {
				g.edgeAt(parentID, nodeID, "spawned", int(ev.Severity), ev.Time)
			}
		}
	}

	// Suspicious flagging deferred to detection engine alerts
	// Nodes are flagged suspicious via alert correlation, not heuristics
}

func (g *graphBuilder) handleNetwork(ev store.Event) {
	if ev.DstIP == nil || *ev.DstIP == "" {
		return
	}
	dstIP := *ev.DstIP
	dstPort := 0
	if ev.DstPort != nil {
		dstPort = *ev.DstPort
	}

	// Skip loopback
	if isLoopback(dstIP) {
		return
	}

	isExt := isExternal(dstIP)
	sev    := int(ev.Severity)
	if isExt && sev < 2 {
		sev = 2
	}

	procNodeID := g.findProcessNode(ev)

	// Only create explicit IP nodes for:
	//   - High/critical severity connections (detection engine scored them)
	//   - Connections to well-known shell/C2 ports (structural — not application-specific)
	// Everything else aggregates as a counter on the process node.
	createNode := sev >= 4 || wellKnownShellPorts[dstPort]

	if createNode {
		ipLabel  := fmt.Sprintf("%s:%d", dstIP, dstPort)
		ipNodeID := fmt.Sprintf("ip-%s-%d", dstIP, dstPort)
		ipNode   := g.node(ipNodeID, "ip", ipLabel, sev)
		g.nodeAt(ipNode, ev.Time)
		ipNode.Meta["ip"]          = dstIP
		ipNode.Meta["port"]        = dstPort
		ipNode.Meta["is_external"] = isExt
		if ev.Proto != nil {
			ipNode.Meta["proto"] = *ev.Proto
		}
		if ev.ID != "" {
			ipNode.Meta["event_ids"] = append(nodeEventIDs(ipNode), ev.ID)
		}
		if procNodeID != "" {
			g.edgeAt(procNodeID, ipNodeID, "connected", sev, ev.Time)
		}
	} else if procNodeID != "" {
		// Aggregate into process node as connection summary
		proc := g.nodes[procNodeID]
		if proc != nil {
			// Track top connections as metadata on the process node
			conns, _ := proc.Meta["top_connections"].([]map[string]interface{})
			entry := map[string]interface{}{"ip": dstIP, "port": dstPort, "ext": isExt}
			// Deduplicate by ip:port — increment count
			found := false
			for _, c := range conns {
				if c["ip"] == dstIP && c["port"] == dstPort {
					c["count"] = func() int { v, _ := c["count"].(int); return v + 1 }()
					found = true
					break
				}
			}
			if !found && len(conns) < 20 {
				entry["count"] = 1
				conns = append(conns, entry)
			}
			proc.Meta["top_connections"] = conns
			proc.Meta["total_connections"] = func() int { v, _ := proc.Meta["total_connections"].(int); return v + 1 }()
		}
	}
}

func (g *graphBuilder) handleDNS(ev store.Event) {
	if ev.DstIP == nil || *ev.DstIP == "" {
		return
	}
	domain := *ev.DstIP // DNS events store domain in DstIP field

	// Skip if it's actually an IP (Linux stores DNS server IP not domain)
	if isIPAddress(domain) {
		return
	}
	// Skip local/mDNS lookups
	if strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".internal") ||
		strings.HasSuffix(domain, ".arpa") || domain == "localhost" {
		return
	}

	dnsNodeID := fmt.Sprintf("dns-%s", strings.ToLower(domain))
	sev := int(ev.Severity)

	dnsNode := g.node(dnsNodeID, "dns", domain, sev)
	g.nodeAt(dnsNode, ev.Time)
	dnsNode.Meta["domain"] = domain
	// Store event ID for alert correlation
	if ev.ID != "" {
		dnsNode.Meta["event_ids"] = append(nodeEventIDs(dnsNode), ev.ID)
	}

	// Extract resolved IPs from QueryResults if available
	if ev.Raw != nil {
		rawMap := rawToMap(ev.Raw)
		if qr, ok := rawMap["query_results"].(string); ok && qr != "" {
			dnsNode.Meta["resolved_ips"] = parseQueryResults(qr)
		}
		if qt, ok := rawMap["query_type"].(string); ok {
			dnsNode.Meta["query_type"] = qt
		}
	}

	// Link process → dns
	procNodeID := g.findProcessNode(ev)
	if procNodeID != "" {
		g.edgeAt(procNodeID, dnsNodeID, "queried", sev, ev.Time)
	}
}

func (g *graphBuilder) handleFile(ev store.Event) {
	if ev.FilePath == nil || *ev.FilePath == "" {
		return
	}
	path := *ev.FilePath

	// Skip virtual/kernel filesystems — cross-platform, path-prefix based only.
	pathLow := strings.ToLower(path)
	skipPrefixes := []string{
		"/proc/",  // Linux kernel virtual fs
		"/sys/",   // Linux sysfs
		"/dev/",   // Linux devices
		"/run/",   // Linux runtime sockets/pids
	}
	for _, p := range skipPrefixes {
		if strings.HasPrefix(pathLow, p) {
			return
		}
	}
	// Skip by extension — noisy temp/cache files from any application on any OS.
	skipSuffixes := []string{
		".log", ".tmp", ".cache", ".lock",
		".db-shm", ".db-wal", ".crdownload", ".part", ".swp", ".swo",
	}
	for _, s := range skipSuffixes {
		if strings.HasSuffix(pathLow, s) {
			return
		}
	}
	// Core rule: trust the detection engine severity. Info events on non-sensitive
	// paths are skipped. Any event the detection engine scored >= 2 appears,
	// regardless of which process wrote it or what OS it came from.
	if int(ev.Severity) <= 1 && !isSensitivePath(path) {
		return
	}
	// Normalize path length
	if len(path) > 120 {
		path = "..." + path[len(path)-117:]
	}

	fileNodeID := fmt.Sprintf("file-%s", strings.ToLower(path))
	sev := int(ev.Severity)

	action := "modified"
	if ev.Raw != nil {
		if rawMap := rawToMap(ev.Raw); rawMap != nil {
			if a, ok := rawMap["action"].(string); ok {
				action = a
			}
		}
	}

	fileNode := g.node(fileNodeID, "file", fileBasename(path), sev)
	g.nodeAt(fileNode, ev.Time)
	fileNode.Meta["path"] = path
	fileNode.Meta["action"] = action
	if ev.FileHash != nil && *ev.FileHash != "" {
		fileNode.Meta["hash"] = *ev.FileHash
	}
	// Flag files in sensitive paths - this is structural, not heuristic
	if isSensitivePath(path) && fileNode.Severity < 3 {
		fileNode.Severity = 3
	}
	// Store event ID for alert correlation
	if ev.ID != "" {
		fileNode.Meta["event_ids"] = append(nodeEventIDs(fileNode), ev.ID)
	}

	// Link process → file (direct if PID available)
	procNodeID := g.findProcessNode(ev)
	edgeType := fileActionToEdgeType(action)
	if procNodeID != "" {
		g.edgeAt(procNodeID, fileNodeID, edgeType, sev, ev.Time)
	} else {
		// Store unlinked for proximity matching later
		fileNode.Meta["unlinked"] = true
		fileNode.Meta["event_time"] = ev.Time
		fileNode.Meta["user"] = strOrEmpty(ev.UserName)
	}
}

func (g *graphBuilder) handleRegistry(ev store.Event) {
	if ev.RegKey == nil || *ev.RegKey == "" {
		return
	}
	key := *ev.RegKey
	label := key
	if len(label) > 80 {
		label = "..." + label[len(label)-77:]
	}

	regNodeID := fmt.Sprintf("reg-%s", strings.ToLower(key))
	sev := int(ev.Severity)

	regNode := g.node(regNodeID, "registry", label, sev)
	g.nodeAt(regNode, ev.Time)
	regNode.Meta["key"] = key
	if ev.RegValue != nil {
		regNode.Meta["value"] = *ev.RegValue
	}
	if ev.RegData != nil {
		regNode.Meta["data"] = *ev.RegData
	}
	// Flag known persistence keys - structural fact, not heuristic
	if isPersistenceKey(key) && regNode.Severity < 4 {
		regNode.Severity = 4
	}
	// Store event ID for alert correlation
	if ev.ID != "" {
		regNode.Meta["event_ids"] = append(nodeEventIDs(regNode), ev.ID)
	}

	procNodeID := g.findProcessNode(ev)
	if procNodeID != "" {
		g.edgeAt(procNodeID, regNodeID, "modified", sev, ev.Time)
	} else {
		regNode.Meta["unlinked"] = true
		regNode.Meta["event_time"] = ev.Time
		regNode.Meta["user"] = strOrEmpty(ev.UserName)
	}
}

func (g *graphBuilder) handleLogon(ev store.Event) {
	user := strOrEmpty(ev.UserName)
	if user == "" {
		return
	}

	logonNodeID := fmt.Sprintf("logon-%s", strings.ToLower(user))
	sev := int(ev.Severity)

	logonNode := g.node(logonNodeID, "logon", user, sev)
	logonNode.Meta["user"] = user
	if ev.Domain != nil {
		logonNode.Meta["domain"] = *ev.Domain
	}
	if ev.EventID != nil {
		logonNode.Meta["event_id"] = *ev.EventID
		if *ev.EventID == 4625 { // Failed logon
			logonNode.Suspicious = true
			logonNode.Severity = 3
		}
	}
	if ev.SrcIP != nil && *ev.SrcIP != "" {
		logonNode.Meta["src_ip"] = *ev.SrcIP
		// Link to IP node if exists
		srcIPID := fmt.Sprintf("ip-%s-0", *ev.SrcIP)
		if _, ok := g.nodes[srcIPID]; !ok {
			ipNode := g.node(srcIPID, "ip", *ev.SrcIP, sev)
			ipNode.Meta["ip"] = *ev.SrcIP
			ipNode.Meta["is_external"] = isExternal(*ev.SrcIP)
		}
		g.edgeAt(srcIPID, logonNodeID, "auth", sev, ev.Time)
	}
}

// proximityMatch links file/registry events to processes by time proximity
// when PID is not available (Windows FIM, kqueue, inotify).
func (g *graphBuilder) proximityMatch(events []store.Event) {
	// Build timeline of process events: time → [pid, name]
	type procAt struct {
		pid      int
		name     string
		start    time.Time
		lastSeen time.Time
		user     string
	}
	// Build process time windows: pid → {start, lastSeen}
	procWindows := make(map[int]*procAt)
	for _, ev := range events {
		if ev.ProcessName == nil || ev.PID == nil { continue }
		pid := *ev.PID
		if pid == 0 { continue }
		name := *ev.ProcessName
		if p, ok := procWindows[pid]; ok {
			if ev.Time.After(p.lastSeen) { p.lastSeen = ev.Time }
		} else {
			procWindows[pid] = &procAt{
				pid: pid, name: name, start: ev.Time, lastSeen: ev.Time,
				user: strOrEmpty(ev.UserName),
			}
		}
	}
	var procTimeline []*procAt
	for _, p := range procWindows {
		procTimeline = append(procTimeline, p)
	}
	sort.Slice(procTimeline, func(i, j int) bool {
		return procTimeline[i].start.Before(procTimeline[j].start)
	})

	// For each unlinked file/registry node, find nearest process in time
	for _, node := range g.nodes {
		if _, unlinked := node.Meta["unlinked"]; !unlinked {
			continue
		}
		evTime, _ := node.Meta["event_time"].(time.Time)
		evUser, _ := node.Meta["user"].(string)

		window := 30 * time.Second
		var best *procAt
		bestScore := -1

		for _, p := range procTimeline {
			// Process must have been running at the time of the file event
			// (started before evTime + window, still alive after evTime - window)
			if p.start.After(evTime.Add(window)) { continue }
			if p.lastSeen.Before(evTime.Add(-window)) { continue }

			score := 0
			if evUser != "" && p.user == evUser { score += 10 }
			// Closer in time = better
			delta := evTime.Sub(p.start)
			if delta < 0 { delta = -delta }
			if delta < 5*time.Second { score += 5 }
			if delta < 15*time.Second { score += 3 }

			if score > bestScore {
				bestScore = score
				best = p
			}
		}

		if best != nil {
			procNodeID := fmt.Sprintf("proc-%s-%d", strings.ToLower(best.name), best.pid)
			if _, exists := g.nodes[procNodeID]; exists {
				edgeType := "modified"
				if node.Type == "file" {
					if a, ok := node.Meta["action"].(string); ok {
						edgeType = fileActionToEdgeType(a)
					}
				}
				g.edge(procNodeID, node.ID, edgeType, node.Severity)
			}
		}

		delete(node.Meta, "unlinked")
		delete(node.Meta, "event_time")
	}
}

// findProcessNode returns the process node ID for an event based on PID or ProcessName.
func (g *graphBuilder) findProcessNode(ev store.Event) string {
	// Try direct PID lookup
	if ev.PID != nil && *ev.PID > 0 {
		if n, ok := g.pidProc[*ev.PID]; ok {
			return n.ID
		}
		// PID known but node not yet created — use name from cache
		if name, ok := g.pidName[*ev.PID]; ok {
			nodeID := fmt.Sprintf("proc-%s-%d", strings.ToLower(name), *ev.PID)
			if _, exists := g.nodes[nodeID]; exists {
				return nodeID
			}
			// Create minimal process node
			n := g.node(nodeID, "process", name, 1)
			n.Meta["pid"] = *ev.PID
			g.pidProc[*ev.PID] = n
			return nodeID
		}
	}

	// Try ProcessName lookup (find any node with this name)
	if ev.ProcessName != nil && *ev.ProcessName != "" {
		name := strings.ToLower(*ev.ProcessName)
		for id, n := range g.nodes {
			if n.Type == "process" && strings.ToLower(n.Label) == name {
				return id
			}
		}
	}
	return ""
}

func (g *graphBuilder) build() EndpointGraph {
	hostNodeID := fmt.Sprintf("host-%s", g.host)
	hostNode := g.node(hostNodeID, "host", g.host, 1)
	hostNode.Meta["os"] = g.os
	hostNode.Meta["agent_id"] = g.agentID

	// Connect all root processes to host
	for _, n := range g.nodes {
		if n.Type != "process" {
			continue
		}
		ppid, _ := n.Meta["ppid"].(int)
		if ppid == 0 || g.pidProc[ppid] == nil {
			g.edge(hostNodeID, n.ID, "runs", 1)
		}
	}

	graph := EndpointGraph{}
	graph.Meta.Host = g.host
	graph.Meta.Since = time.Now().Add(-24 * time.Hour)
	graph.Meta.OS = g.os
	graph.Meta.AgentID = g.agentID

	for _, n := range g.nodes {
		graph.Nodes = append(graph.Nodes, *n)
		graph.Meta.EventCount += n.EventCount
	}
	for _, e := range g.edges {
		graph.Edges = append(graph.Edges, *e)
	}

	// Sort by severity desc
	sort.Slice(graph.Nodes, func(i, j int) bool {
		return graph.Nodes[i].Severity > graph.Nodes[j].Severity
	})
	return graph
}

// ── Handler ───────────────────────────────────────────────────────────────────

func handleEndpointGraph(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 168 {
				hours = n
			}
		}

		// Optional process filter — only show graph for specific process
		processFilter := r.URL.Query().Get("process")

		since := time.Now().Add(-time.Duration(hours) * time.Hour)
		filter := store.EventFilter{
			Host:  host,
			Since: since,
			Limit: 10000,
		}
		if processFilter != "" {
			filter.ProcessName = processFilter
		}
		events, _, err := db.QueryEvents(r.Context(), filter)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		builder := newGraphBuilder(host)
		builder.processEvents(events)
		graph := builder.build()
		graph.Meta.Since = since
		graph.Meta.EventCount = len(events)

		// Correlate detection engine alerts — mark nodes suspicious based on real alerts
		// not heuristics. Pull open alerts for this host in the time window.
		alerts, _ := db.ListAlertsForHost(r.Context(), host, since)
		alertsByEventID := make(map[string]store.Alert)
		for _, a := range alerts {
			if a.SourceEventID != "" {
				alertsByEventID[a.SourceEventID] = a
			}
		}
		// Mark nodes suspicious via real detection engine alerts
		for i := range graph.Nodes {
			n := &graph.Nodes[i]
			if n.Meta == nil {
				continue
			}
			// Match any of the node's event IDs against alert SourceEventIDs
			if ids, ok := n.Meta["event_ids"].([]string); ok {
				for _, eid := range ids {
					if alert, hit := alertsByEventID[eid]; hit {
						n.Suspicious = true
						if alert.Severity > n.Severity {
							n.Severity = alert.Severity
						}
						n.Meta["alert_title"] = alert.Title
						n.Meta["alert_severity"] = alert.Severity
						break
					}
				}
			}
			// Severity >= 4 from detection engine signatures also flags suspicious
			if n.Severity >= 4 {
				n.Suspicious = true
			}
		}

		writeJSON(w, 200, graph)
	}
}

// ── Cloud graph handler ───────────────────────────────────────────────────────

func handleCloudGraph(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if n, err := strconv.Atoi(h); err == nil && n > 0 {
				hours = n
			}
		}
		since := time.Now().Add(-time.Duration(hours) * time.Hour)

		// Query all cloud events
		cloudTypes := []string{"cloud.cloudtrail", "cloud.azure_activity", "cloud.gcp_audit",
			"cloud.guardduty", "cloud.entra_signin"}

		var allEvents []store.Event
		for _, et := range cloudTypes {
			evs, _, err := db.QueryEvents(r.Context(), store.EventFilter{
				EventType: et,
				Since:     since,
				Limit:     2000,
			})
			if err == nil {
				allEvents = append(allEvents, evs...)
			}
		}

		graph := buildCloudGraph(allEvents, since)
		writeJSON(w, 200, graph)
	}
}

// ── Network graph handler ─────────────────────────────────────────────────────

func handleNetworkGraph(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if n, err := strconv.Atoi(h); err == nil && n > 0 {
				hours = n
			}
		}
		since := time.Now().Add(-time.Duration(hours) * time.Hour)

		// Query all network events across all hosts
		events, _, err := db.QueryEvents(r.Context(), store.EventFilter{
			EventType: "network",
			Since:     since,
			Limit:     10000,
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		// Query agents table for known hosts with IPs and OS info
		agentRows, _ := db.QueryContext(r.Context(), `
			SELECT hostname, COALESCE(last_ip,''), os, last_seen
			FROM agents ORDER BY last_seen DESC`)
		agentsByHost := make(map[string]agentInfo)
		agentsByIP := make(map[string]string) // ip → hostname
		if agentRows != nil {
			defer agentRows.Close()
			for agentRows.Next() {
				var a agentInfo
				var lastSeen time.Time
				if err := agentRows.Scan(&a.hostname, &a.lastIP, &a.os, &lastSeen); err == nil {
					agentsByHost[a.hostname] = a
					if a.lastIP != "" {
						agentsByIP[a.lastIP] = a.hostname
					}
				}
			}
		}

		graph := buildNetworkGraph(events, since, agentsByHost, agentsByIP)
		writeJSON(w, 200, graph)
	}
}

// ── Cloud graph builder ───────────────────────────────────────────────────────

type CloudGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
	Meta  struct {
		Since      time.Time `json:"since"`
		EventCount int       `json:"event_count"`
	} `json:"meta"`
}

func buildCloudGraph(events []store.Event, since time.Time) CloudGraph {
	nodes := make(map[string]*GraphNode)
	edges := make(map[string]*GraphEdge)

	addNode := func(id, typ, label string, sev int) *GraphNode {
		if n, ok := nodes[id]; ok {
			n.EventCount++
			if sev > n.Severity { n.Severity = sev }
			return n
		}
		n := &GraphNode{ID: id, Type: typ, Label: label, Severity: sev,
			EventCount: 1, Meta: make(map[string]interface{})}
		nodes[id] = n
		return n
	}
	addEdge := func(src, dst, typ string, sev int) {
		id := fmt.Sprintf("%s→%s[%s]", src, dst, typ)
		if e, ok := edges[id]; ok { e.Count++; return }
		edges[id] = &GraphEdge{ID: id, Source: src, Target: dst, Type: typ, Count: 1, Severity: sev}
	}

	for _, ev := range events {
		raw := rawToMap(ev.Raw)
		if raw == nil { continue }

		provider := cloudProviderFromEventType(ev.EventType)
		accountID, _ := raw["account_id"].(string)
		if accountID == "" {
			// connector_id is stored as float64 by json.Unmarshal
			if cid, ok := raw["connector_id"].(float64); ok {
				accountID = fmt.Sprintf("%d", int64(cid))
			} else if cid, ok := raw["connector_id"].(string); ok {
				accountID = cid
			} else {
				accountID = "unknown"
			}
		}

		// Account node
		accountNodeID := fmt.Sprintf("cloud-%s-%s", provider, accountID)
		addNode(accountNodeID, "cloud_account", fmt.Sprintf("%s: %s", strings.ToUpper(provider), accountID), 1)

		// Identity node
		identity := strOrEmpty(ev.UserName)
		if identity == "" {
			if caller, ok := raw["caller"].(string); ok { identity = caller }
			if username, ok := raw["username"].(string); ok { identity = username }
		}
		if identity == "" { identity = "unknown" }

		// Scope identity to account to avoid collapsing different accounts' users
		identityNodeID := fmt.Sprintf("identity-%s-%s", accountID, strings.ToLower(identity))
		identityNode := addNode(identityNodeID, "identity", identity, int(ev.Severity))
		identityNode.Meta["provider"] = provider
		identityNode.Meta["account"] = accountID
		addEdge(accountNodeID, identityNodeID, "contains", 1)

		// Action / operation node
		operation := ""
		if evName, ok := raw["event_name"].(string); ok { operation = evName }
		if opName, ok := raw["operation_name"].(string); ok { operation = opName }
		if method, ok := raw["method_name"].(string); ok { operation = method }
		if findType, ok := raw["finding_type"].(string); ok { operation = findType }
		if operation == "" { continue }

		// Scope operation to identity so same op by different users shows separately
		opNodeID := fmt.Sprintf("op-%s-%s-%s", provider, strings.ToLower(identity), strings.ToLower(operation))
		opNode := addNode(opNodeID, "api_call", operation, int(ev.Severity))
		opNode.Meta["provider"] = provider
		opNode.Meta["source"] = ev.Source
		if ev.Severity >= 4 { opNode.Suspicious = true }
		addEdge(identityNodeID, opNodeID, "called", int(ev.Severity))

		// Source IP node
		srcIP := strOrEmpty(ev.SrcIP)
		if srcIP != "" && !isLoopback(srcIP) {
			ipNodeID := fmt.Sprintf("cloud-ip-%s", srcIP)
			ipNode := addNode(ipNodeID, "ip", srcIP, 1)
			ipNode.Meta["is_external"] = isExternal(srcIP)
			addEdge(ipNodeID, identityNodeID, "from_ip", 1)
		}

		// Resource node (AWS resource ARN, Azure resource ID, GCP resource)
		resource := ""
		if resID, ok := raw["resource_id"].(string); ok { resource = resID }
		if res, ok := raw["resource"].(map[string]interface{}); ok {
			if resType, ok := res["ResourceType"].(string); ok { resource = resType }
		}
		if resource != "" && len(resource) < 100 {
			resLabel := resource
			if len(resLabel) > 50 { resLabel = "..." + resLabel[len(resLabel)-47:] }
			resNodeID := fmt.Sprintf("resource-%s", strings.ToLower(resource))
			addNode(resNodeID, "resource", resLabel, int(ev.Severity))
			addEdge(opNodeID, resNodeID, "accessed", int(ev.Severity))
		}
	}

	graph := CloudGraph{}
	graph.Meta.Since = since
	graph.Meta.EventCount = len(events)
	for _, n := range nodes { graph.Nodes = append(graph.Nodes, *n) }
	for _, e := range edges { graph.Edges = append(graph.Edges, *e) }
	return graph
}

// ── Network graph builder ─────────────────────────────────────────────────────

type NetworkGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
	Meta  struct {
		Since      time.Time `json:"since"`
		EventCount int       `json:"event_count"`
	} `json:"meta"`
}

func buildNetworkGraph(events []store.Event, since time.Time, agentsByHost map[string]agentInfo, agentsByIP map[string]string) NetworkGraph {
	nodes := make(map[string]*GraphNode)
	edges := make(map[string]*GraphEdge)

	addNode := func(id, typ, label string, sev int) *GraphNode {
		if n, ok := nodes[id]; ok {
			n.EventCount++
			if sev > n.Severity { n.Severity = sev }
			return n
		}
		n := &GraphNode{ID: id, Type: typ, Label: label, Severity: sev,
			EventCount: 1, Meta: make(map[string]interface{})}
		nodes[id] = n
		return n
	}
	addEdge := func(src, dst, typ string, sev int) {
		id := fmt.Sprintf("%s→%s[%s]", src, dst, typ)
		if e, ok := edges[id]; ok { e.Count++; if sev > e.Severity { e.Severity = sev }; return }
		edges[id] = &GraphEdge{ID: id, Source: src, Target: dst, Type: typ, Count: 1, Severity: sev}
	}

	// Seed device nodes from agents table — richer than inferring from events
	for hostname, agent := range agentsByHost {
		nodeID := fmt.Sprintf("device-%s", hostname)
		n := addNode(nodeID, "device", hostname, 1)
		n.Meta["os"] = agent.os
		n.Meta["ip"] = agent.lastIP
		n.Meta["has_agent"] = true
	}

	// Also build hostIPs from agents table (more reliable than SrcIP from events)
	hostIPs := make(map[string]string) // hostname → IP
	for hostname, agent := range agentsByHost {
		if agent.lastIP != "" {
			hostIPs[hostname] = agent.lastIP
		}
	}
	// Supplement with SrcIPs from events for hosts not in agents table
	for _, ev := range events {
		if _, known := hostIPs[ev.Host]; !known {
			if ev.SrcIP != nil && *ev.SrcIP != "" {
				hostIPs[ev.Host] = *ev.SrcIP
			}
		}
	}

	// Ensure all event hosts have device nodes
	for _, ev := range events {
		nodeID := fmt.Sprintf("device-%s", ev.Host)
		if _, exists := nodes[nodeID]; !exists {
			n := addNode(nodeID, "device", ev.Host, 1)
			n.Meta["os"] = ev.OS
			n.Meta["ip"] = hostIPs[ev.Host]
			n.Meta["has_agent"] = agentsByHost[ev.Host].hostname != ""
		}
	}

	// Connection edges
	for _, ev := range events {
		if ev.DstIP == nil || *ev.DstIP == "" { continue }
		dstIP := *ev.DstIP
		dstPort := 0
		if ev.DstPort != nil { dstPort = *ev.DstPort }
		sev := int(ev.Severity)

		srcDeviceID := fmt.Sprintf("device-%s", ev.Host)

		// Is destination another known agent host?
		dstHostname := agentsByIP[dstIP]
		if dstHostname == "" {
			// Try matching against observed hostIPs
			for host, ip := range hostIPs {
				if ip == dstIP {
					dstHostname = host
					break
				}
			}
		}

		if dstHostname != "" && dstHostname != ev.Host {
			// Internal — agent to agent
			dstDeviceID := fmt.Sprintf("device-%s", dstHostname)
			edgeID := fmt.Sprintf("%s→%s[connected]", srcDeviceID, dstDeviceID)
			addEdge(srcDeviceID, dstDeviceID, "connected", sev)
			// Promote to lateral movement on SMB/RDP/SSH/WinRM
			if dstPort == 445 || dstPort == 3389 || dstPort == 22 || dstPort == 5985 || dstPort == 5986 {
				if e, ok := edges[edgeID]; ok {
					e.Type = "lateral"
					if e.Severity < 3 { e.Severity = 3 }
				}
			}
		} else if !isLoopback(dstIP) && isExternal(dstIP) {
			extLabel := fmt.Sprintf("%s:%d", dstIP, dstPort)
			extNodeID := fmt.Sprintf("ext-%s-%d", dstIP, dstPort)
			extNode := addNode(extNodeID, "external_ip", extLabel, sev)
			extNode.Meta["ip"] = dstIP
			extNode.Meta["port"] = dstPort
			extNode.Meta["is_external"] = true
			addEdge(srcDeviceID, extNodeID, "connected", sev)
		} else if isInternal(dstIP) && dstHostname == "" && !isLoopback(dstIP) {
			// Internal IP with no agent — unknown device
			unknownID := fmt.Sprintf("unknown-%s", dstIP)
			unknownNode := addNode(unknownID, "unknown_device", dstIP, 2)
			unknownNode.Meta["ip"] = dstIP
			unknownNode.Meta["has_agent"] = false
			addEdge(srcDeviceID, unknownID, "connected", sev)
		}
	}

	graph := NetworkGraph{}
	graph.Meta.Since = since
	graph.Meta.EventCount = len(events)
	for _, n := range nodes { graph.Nodes = append(graph.Nodes, *n) }
	for _, e := range edges { graph.Edges = append(graph.Edges, *e) }
	return graph
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isLoopback(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1" || ip == "0.0.0.0"
}

func isInternal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil { return false }
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"}
	for _, cidr := range private {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(parsed) { return true }
	}
	return false
}

func isExternal(ip string) bool {
	return !isLoopback(ip) && !isInternal(ip)
}

func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// Suspicious detection is handled by the detection engine alert pipeline.
// Graph nodes are marked suspicious via alert correlation (see handleEndpointGraph).
// The following functions handle structural facts only — not heuristic detection.

func isSensitivePath(path string) bool {
	// These are security-relevant paths across all three platforms.
	// Uses Contains so partial paths match (e.g. ".ssh/" matches any user's ~/.ssh/).
	sensitive := []string{
		// Linux credential/config files
		"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab",
		"/etc/cron.", "/etc/ssh/", "/etc/hosts",
		// SSH keys — all platforms
		".ssh/", "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys", "known_hosts",
		// Cloud credentials — all platforms
		".aws/credentials", ".aws/config", ".azure/", ".gcp/",
		"gcloud/credentials", "application_default_credentials",
		// Windows credential/system paths
		"system32", "\\SAM", "\\NTDS", "\\SECURITY", "lsass",
		"\\AppData\\Roaming\\Microsoft\\Credentials",
		"\\AppData\\Local\\Microsoft\\Credentials",
		// macOS credential paths
		"Library/Keychains/", "login.keychain", "TCC.db",
		"/private/etc/", "Library/LaunchAgents/", "Library/LaunchDaemons/",
		// Cross-platform secrets
		".env", ".env.local", ".env.production",
		"kdbx", "wallet.dat", "keystore",
		// Docker/k8s credentials
		".docker/config.json", "kubeconfig", "/.kube/",
	}
	pathLower := strings.ToLower(path)
	for _, s := range sensitive {
		if strings.Contains(pathLower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func isPersistenceKey(key string) bool {
	persistence := []string{
		"CurrentVersion\\Run", "CurrentVersion\\RunOnce",
		"CurrentVersion\\RunServices", "Winlogon",
		"Image File Execution Options", "AppInit_DLLs",
		"BootExecute", "ServiceDLL",
	}
	keyLower := strings.ToLower(key)
	for _, p := range persistence {
		if strings.Contains(keyLower, strings.ToLower(p)) { return true }
	}
	return false
}

func fileActionToEdgeType(action string) string {
	switch action {
	case "create", "creat": return "created"
	case "delete", "deleted", "unlink": return "deleted"
	case "exec", "executed": return "executed"
	default: return "wrote"
	}
}

func fileBasename(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		parts = strings.Split(path, "\\")
	}
	return parts[len(parts)-1]
}

// nodeEventIDs returns the list of event IDs stored in a node's Meta.
func nodeEventIDs(n *GraphNode) []string {
	if n.Meta == nil {
		return nil
	}
	if ids, ok := n.Meta["event_ids"].([]string); ok {
		return ids
	}
	return nil
}

func strOrEmpty(s *string) string {
	if s == nil { return "" }
	return *s
}

func rawToMap(raw []byte) map[string]interface{} {
	if raw == nil { return nil }
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil { return nil }
	return m
}

func parseQueryResults(results string) []string {
	// QueryResults format: "type: ip1; type: ip2;" or "ip1\nip2"
	var ips []string
	for _, part := range strings.FieldsFunc(results, func(r rune) bool {
		return r == ';' || r == '\n' || r == ','
	}) {
		part = strings.TrimSpace(part)
		if idx := strings.LastIndex(part, " "); idx >= 0 {
			part = part[idx+1:]
		}
		if isIPAddress(part) {
			ips = append(ips, part)
		}
	}
	return ips
}

func cloudProviderFromEventType(et string) string {
	switch {
	case strings.Contains(et, "cloudtrail") || strings.Contains(et, "guardduty"): return "aws"
	case strings.Contains(et, "azure") || strings.Contains(et, "entra"): return "azure"
	case strings.Contains(et, "gcp"): return "gcp"
	default: return "cloud"
	}
}



// handleEndpointProcesses returns a list of unique processes seen on a host
// with their event counts, severity, and suspicious flag
func handleEndpointProcesses(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 168 {
				hours = n
			}
		}

		since := time.Now().Add(-time.Duration(hours) * time.Hour)

		// Get all events for this host
		events, _, err := db.QueryEvents(r.Context(), store.EventFilter{
			Host:  host,
			Since: since,
			Limit: 20000,
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		// Get alerts for this host to mark suspicious processes
		alerts, _ := db.ListAlertsForHost(r.Context(), host, since)
		suspiciousProcesses := map[string]bool{}
		alertsByProcess := map[string]string{}
		for _, a := range alerts {
			if a.EventType == "process" || a.Title != "" {
				// Extract process name from alert if available
				suspiciousProcesses[a.Host] = true
			}
		}
		_ = alertsByProcess

		type ProcessInfo struct {
			Name        string    `json:"name"`
			EventCount  int       `json:"event_count"`
			MaxSeverity int       `json:"max_severity"`
			Suspicious  bool      `json:"suspicious"`
			FirstSeen   time.Time `json:"first_seen"`
			LastSeen    time.Time `json:"last_seen"`
			Types       []string  `json:"types"` // event types seen for this process
		}

		procs := map[string]*ProcessInfo{}
		typeSeen := map[string]map[string]bool{}

		for _, ev := range events {
			name := ""
			if ev.ProcessName != nil && *ev.ProcessName != "" {
				name = *ev.ProcessName
			} else {
				continue // skip events with no process name
			}

			if _, ok := procs[name]; !ok {
				procs[name] = &ProcessInfo{
					Name:      name,
					FirstSeen: ev.Time,
					LastSeen:  ev.Time,
				}
				typeSeen[name] = map[string]bool{}
			}
			p := procs[name]
			p.EventCount++
			if ev.Severity > p.MaxSeverity {
				p.MaxSeverity = ev.Severity
			}
			if ev.Time.Before(p.FirstSeen) { p.FirstSeen = ev.Time }
			if ev.Time.After(p.LastSeen)  { p.LastSeen  = ev.Time }
			typeSeen[name][ev.EventType] = true
			if ev.Severity >= 4 { p.Suspicious = true }
		}

		// Build result list sorted by event count descending
		var result []ProcessInfo
		for name, p := range procs {
			for t := range typeSeen[name] { p.Types = append(p.Types, t) }
			if suspiciousProcesses[name] { p.Suspicious = true }
			result = append(result, *p)
		}
		// Sort: suspicious first, then by event count
		for i := 0; i < len(result)-1; i++ {
			for j := i + 1; j < len(result); j++ {
				a, b := result[i], result[j]
				aScore := a.EventCount
				if a.Suspicious { aScore += 100000 }
				bScore := b.EventCount
				if b.Suspicious { bScore += 100000 }
				if bScore > aScore {
					result[i], result[j] = result[j], result[i]
				}
			}
		}

		writeJSON(w, 200, map[string]interface{}{
			"host":      host,
			"processes": result,
			"total":     len(result),
			"since":     since,
		})
	}
}
