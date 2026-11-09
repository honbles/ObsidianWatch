package api

// cloud_gcp_blast_radius.go — Resource relationship mapping and blast radius analysis.
//
// Answers: "If this resource is compromised, what can the attacker reach?"
//
// Builds a directed graph of resource relationships:
//   ServiceAccount → (used by) → VM, CloudFunction, CloudRun
//   ServiceAccount → (has role) → Project IAM
//   VM → (has SA) → ServiceAccount
//   VM → (on subnet) → Subnet → VPC → Firewall rules
//   Bucket → (allUsers ACL) → Public
//   SQL → (authorized network) → IP ranges
//   KMS Key → (encrypts) → Disk, Bucket, Secret
//   Secret → (accessed by) → ServiceAccount
//
// For each resource with a CSPM finding, we trace:
//   1. What does this resource have access to? (outbound edges)
//   2. What resources depend on this? (inbound edges)
//   3. What is the maximum privilege reachable from here?

import (
	"sort"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Graph Types ───────────────────────────────────────────────────────────────

type BlastNode struct {
	ID           string            `json:"id"`           // unique node id
	Name         string            `json:"name"`         // short display name
	FullName     string            `json:"full_name"`    // full resource path
	Type         string            `json:"type"`         // vm, sa, bucket, sql, secret, network, firewall
	Risk         string            `json:"risk"`         // critical, high, medium, low, none
	HasFindings  bool              `json:"has_findings"`
	FindingCount int               `json:"finding_count"`
	Labels       map[string]string `json:"labels,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"` // key facts
}

type BlastEdge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"` // "uses_sa", "on_subnet", "has_role", "encrypts", "can_access"
	RiskBoost    bool   `json:"risk_boost"`   // does this edge amplify blast radius?
}

type BlastRadiusResult struct {
	ConnectorID  int64                  `json:"connector_id"`
	ProjectID    string                 `json:"project_id"`
	ScannedAt    time.Time              `json:"scanned_at"`
	Nodes        []BlastNode            `json:"nodes"`
	Edges        []BlastEdge            `json:"edges"`
	HighRiskPaths []BlastPath           `json:"high_risk_paths"`
	Summary      BlastSummary           `json:"summary"`
	Errors       []string               `json:"errors,omitempty"`
}

type BlastPath struct {
	StartNode    string   `json:"start_node"`
	Path         []string `json:"path"`
	EndPrivilege string   `json:"end_privilege"` // "project_owner", "all_data", "public", etc.
	Severity     string   `json:"severity"`
	Description  string   `json:"description"`
}

type BlastSummary struct {
	TotalNodes       int `json:"total_nodes"`
	TotalEdges       int `json:"total_edges"`
	CriticalPaths    int `json:"critical_paths"`
	HighRiskNodes    int `json:"high_risk_nodes"`
	PublicExposures  int `json:"public_exposures"`
	PrivEscPaths     int `json:"priv_esc_paths"`
}

// ── Main Engine ───────────────────────────────────────────────────────────────

func RunGCPBlastRadius(ctx context.Context, saJSON, projectID string, cspm *CSPMResult, connID int64) (*BlastRadiusResult, error) {
	start := time.Now()
	result := &BlastRadiusResult{
		ConnectorID: connID,
		ProjectID:   projectID,
		ScannedAt:   start,
	}

	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return nil, fmt.Errorf("invalid SA: %w", err)
	}
	if projectID == "" { projectID = sa.ProjectID }
	result.ProjectID = projectID

	token, err := getGCPTokenWithScope(ctx, sa, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil { return nil, fmt.Errorf("auth: %w", err) }

	// Build finding index for risk annotation
	findingsByResource := make(map[string][]CSPMFinding)
	if cspm != nil {
		for _, f := range cspm.Findings {
			findingsByResource[f.Resource] = append(findingsByResource[f.Resource], f)
		}
	}

	nodes := make(map[string]*BlastNode)
	edges := []*BlastEdge{}

	addNode := func(id, name, fullName, typ string, props map[string]string) *BlastNode {
		if n, ok := nodes[id]; ok { return n }
		n := &BlastNode{
			ID: id, Name: name, FullName: fullName, Type: typ,
			Risk: "none", Properties: props,
		}
		// Annotate risk from CSPM findings
		if findings, ok := findingsByResource[name]; ok && len(findings) > 0 {
			n.HasFindings = true
			n.FindingCount = len(findings)
			for _, f := range findings {
				if sevRank(f.Severity) > sevRank(n.Risk) { n.Risk = f.Severity }
			}
		}
		nodes[id] = n
		return n
	}

	addEdge := func(from, to, rel string, riskBoost bool) {
		edges = append(edges, &BlastEdge{From: from, To: to, Relationship: rel, RiskBoost: riskBoost})
	}

	// ── 1. VMs + Service Accounts ──────────────────────────────────────────
	vms, err := fetchVMsForBlast(ctx, token, projectID)
	if err != nil { result.Errors = append(result.Errors, "vms: "+err.Error()) } else {
		for _, vm := range vms {
			vmID := "vm:" + vm.name
			addNode(vmID, vm.name, vm.fullName, "vm", map[string]string{
				"zone": vm.zone, "status": vm.status,
				"public_ip": vm.publicIP,
			})
			if vm.publicIP != "" {
				pubID := "internet:public"
				addNode(pubID, "Internet", "Internet", "internet", nil)
				n := nodes[vmID]
				if n != nil { n.Risk = maxSev(n.Risk, "high") }
				addEdge(pubID, vmID, "can_reach", true)
				result.Summary.PublicExposures++
			}
			for _, saEmail := range vm.serviceAccounts {
				saID := "sa:" + saEmail
				addNode(saID, saEmail, saEmail, "service_account", nil)
				addEdge(vmID, saID, "uses_sa", true) // VM can act as SA
			}
			netID := "network:" + vm.network
			addNode(netID, shortResourceName(vm.network), vm.network, "network", nil)
			addEdge(vmID, netID, "on_network", false)
		}
	}

	// ── 2. IAM Bindings → Service Accounts ────────────────────────────────
	bindings, err := fetchIAMForBlast(ctx, token, projectID)
	if err != nil { result.Errors = append(result.Errors, "iam: "+err.Error()) } else {
		for _, b := range bindings {
			roleRisk := iamRoleRisk(b.role)
			for _, member := range b.members {
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					pubID := "internet:public"
					addNode(pubID, "Internet", "Internet", "internet", nil)
					roleID := "role:" + b.role
					addNode(roleID, b.role, b.role, "iam_role", map[string]string{"risk": roleRisk})
					nodes[roleID].Risk = roleRisk
					addEdge(pubID, roleID, "has_role", true)
					result.Summary.PublicExposures++
					result.Summary.PrivEscPaths++
					continue
				}
				memberID := "principal:" + member
				memberType := "user"
				if strings.HasPrefix(member, "serviceAccount:") { memberType = "service_account" }
				addNode(memberID, member, member, memberType, map[string]string{"role": b.role})
				roleID := "role:" + b.role
				addNode(roleID, b.role, b.role, "iam_role", map[string]string{"risk": roleRisk})
				if roleRisk == "critical" || roleRisk == "high" {
					nodes[roleID].Risk = roleRisk
					addEdge(memberID, roleID, "has_role", true)
					result.Summary.PrivEscPaths++
				} else {
					addEdge(memberID, roleID, "has_role", false)
				}
			}
		}
	}

	// Impersonation edges: project-level holders of actAs/token-creator style
	// roles can become any service account in the project.
	for _, b := range bindings {
		if !isImpersonationRole(b.role) {
			continue
		}
		for _, member := range b.members {
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				continue
			}
			memberID := "principal:" + member
			addNode(memberID, member, member, "user", map[string]string{"role": b.role})
			for id := range nodes {
				if strings.HasPrefix(id, "sa:") {
					addEdge(memberID, id, "can_impersonate", true)
					result.Summary.PrivEscPaths++
				}
			}
		}
	}

	// ── 3. Storage Buckets ─────────────────────────────────────────────────
	buckets, err := fetchBucketsForBlast(ctx, token, projectID)
	if err != nil { result.Errors = append(result.Errors, "storage: "+err.Error()) } else {
		for _, b := range buckets {
			bID := "bucket:" + b.name
			addNode(bID, b.name, "gs://"+b.name, "storage_bucket", map[string]string{
				"public": fmt.Sprintf("%v", b.isPublic),
			})
			if b.isPublic {
				pubID := "internet:public"
				addNode(pubID, "Internet", "Internet", "internet", nil)
				nodes[bID].Risk = maxSev(nodes[bID].Risk, "critical")
				addEdge(pubID, bID, "can_read", true)
				result.Summary.PublicExposures++
			}
		}
	}

	// ── 4. Firewall Rules ──────────────────────────────────────────────────
	firewalls, err := fetchFirewallsForBlast(ctx, token, projectID)
	if err != nil { result.Errors = append(result.Errors, "firewall: "+err.Error()) } else {
		for _, fw := range firewalls {
			if !fw.openToInternet { continue }
			fwID := "firewall:" + fw.name
			addNode(fwID, fw.name, fw.name, "firewall", map[string]string{
				"ports": strings.Join(fw.ports, ","),
			})
			nodes[fwID].Risk = "high"
			if fw.hasCriticalPort { nodes[fwID].Risk = "critical" }
			pubID := "internet:public"
			addNode(pubID, "Internet", "Internet", "internet", nil)
			netID := "network:" + fw.network
			addNode(netID, shortResourceName(fw.network), fw.network, "network", nil)
			addEdge(pubID, fwID, "allowed_by", true)
			addEdge(fwID, netID, "applies_to", fw.hasCriticalPort)
		}
	}

	// ── 5. Cloud SQL ───────────────────────────────────────────────────────
	sqls, err := fetchSQLForBlast(ctx, token, projectID)
	if err != nil { result.Errors = append(result.Errors, "sql: "+err.Error()) } else {
		for _, s := range sqls {
			sqlID := "sql:" + s.name
			addNode(sqlID, s.name, s.name, "cloud_sql", map[string]string{
				"db_version": s.version, "public_ip": fmt.Sprintf("%v", s.publicIP),
			})
			if s.openToAll {
				pubID := "internet:public"
				addNode(pubID, "Internet", "Internet", "internet", nil)
				nodes[sqlID].Risk = "critical"
				addEdge(pubID, sqlID, "can_connect", true)
				result.Summary.PublicExposures++
			}
		}
	}

	// ── 6. Secrets ────────────────────────────────────────────────────────
	secrets, err := fetchSecretsForBlast(ctx, token, projectID)
	if err != nil { result.Errors = append(result.Errors, "secrets: "+err.Error()) } else {
		for _, s := range secrets {
			secID := "secret:" + s
			addNode(secID, shortResourceName(s), s, "secret", nil)
		}
	}

	// ── Assemble result ────────────────────────────────────────────────────
	nodeList := make([]BlastNode, 0, len(nodes))
	highRisk := 0
	for _, n := range nodes {
		nodeList = append(nodeList, *n)
		if n.Risk == "critical" || n.Risk == "high" { highRisk++ }
	}
	edgeList := make([]BlastEdge, 0, len(edges))
	for _, e := range edges { edgeList = append(edgeList, *e) }

	// ── Trace high-risk paths ──────────────────────────────────────────────
	// Join VM-side and IAM-side views of each service account first (GR-03).
	linked := linkSAIdentities(nodes, edges)
	edges = append(edges, linked...)
	edgeList = edgeList[:0]
	for _, e := range edges { edgeList = append(edgeList, *e) }
	paths := traceHighRiskPaths(nodes, edges)

	result.Nodes = nodeList
	result.Edges = edgeList
	result.HighRiskPaths = paths
	result.Summary.TotalNodes = len(nodeList)
	result.Summary.TotalEdges = len(edgeList)
	result.Summary.HighRiskNodes = highRisk
	result.Summary.CriticalPaths = len(paths)
	return result, nil
}

// ── Path tracing ──────────────────────────────────────────────────────────────

func traceHighRiskPaths(nodes map[string]*BlastNode, edges []*BlastEdge) []BlastPath {
	// Build adjacency list
	adj := make(map[string][]BlastEdge)
	for _, e := range edges {
		if e.RiskBoost {
			adj[e.From] = append(adj[e.From], *e)
		}
	}

	var paths []BlastPath

	// Find all paths from Internet or compromised nodes to high-privilege roles
	startNodes := []string{"internet:public"}
	for id, n := range nodes {
		if n.Risk == "critical" && n.Type != "internet" { startNodes = append(startNodes, id) }
	}

	for _, start := range startNodes {
		visited := make(map[string]bool)
		path := []string{start}
		var dfs func(current string, depth int)
		dfs = func(current string, depth int) {
			if depth > 5 { return }
			if visited[current] { return }
			visited[current] = true
			for _, edge := range adj[current] {
				target := edge.To
				targetNode, ok := nodes[target]
				if !ok { continue }
				newPath := append(append([]string{}, path...), target)

				// Is this a high-value endpoint?
				endPriv := ""
				sev := ""
				desc := ""
				if strings.Contains(target, "roles/owner") || strings.Contains(target, "roles/editor") {
					endPriv = "project_owner_or_editor"
					sev = "critical"
					desc = fmt.Sprintf("Path from %s reaches %s — full project access", start, target)
				} else if targetNode.Type == "storage_bucket" && targetNode.Risk == "critical" {
					endPriv = "public_data_exposure"
					sev = "critical"
					desc = fmt.Sprintf("Path from %s can read all data in bucket %s", start, targetNode.Name)
				} else if targetNode.Type == "cloud_sql" && targetNode.Risk == "critical" {
					endPriv = "database_access"
					sev = "critical"
					desc = fmt.Sprintf("Path from %s can connect to database %s", start, targetNode.Name)
				} else if targetNode.Type == "secret" {
					endPriv = "secret_access"
					sev = "high"
					desc = fmt.Sprintf("Path from %s may access secret %s", start, targetNode.Name)
				}

				if endPriv != "" && len(newPath) >= 2 {
					paths = append(paths, BlastPath{
						StartNode:    start,
						Path:         newPath,
						EndPrivilege: endPriv,
						Severity:     sev,
						Description:  desc,
					})
				}

				path = newPath
				dfs(target, depth+1)
				path = path[:len(path)-1]
			}
			visited[current] = false
		}
		dfs(start, 0)
	}

	// Most severe, then shortest, first — so the 20-path cap below drops the
	// least interesting paths rather than whichever the DFS happened to find last.
	sort.SliceStable(paths, func(i, j int) bool {
		if ri, rj := sevRank(paths[i].Severity), sevRank(paths[j].Severity); ri != rj {
			return ri > rj
		}
		return len(paths[i].Path) < len(paths[j].Path)
	})

	// Deduplicate and limit
	seen := make(map[string]bool)
	unique := []BlastPath{}
	for _, p := range paths {
		key := strings.Join(p.Path, "→")
		if !seen[key] {
			seen[key] = true
			unique = append(unique, p)
		}
		if len(unique) >= 20 { break }
	}
	return unique
}

// ── Data fetchers ─────────────────────────────────────────────────────────────

// G-42: list endpoints are paged; follow nextPageToken up to blastMaxPages.
const blastMaxPages = 20

func gcpPageURL(base, tokenParam, tok string) string {
	if tok == "" {
		return base
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + tokenParam + "=" + url.QueryEscape(tok)
}

type vmBlast struct {
	name, fullName, zone, status, publicIP, network string
	serviceAccounts []string
}

func fetchVMsForBlast(ctx context.Context, token, projectID string) ([]vmBlast, error) {
	baseURL := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances?maxResults=200", projectID)
	var vms []vmBlast
	pageTok := ""
	for page := 0; page < blastMaxPages; page++ {
	var resp struct {
		NextPageToken string `json:"nextPageToken"`
		Items map[string]struct {
			Instances []struct {
				Name            string `json:"name"`
				SelfLink        string `json:"selfLink"`
				Zone            string `json:"zone"`
				Status          string `json:"status"`
				NetworkInterfaces []struct {
					Network       string `json:"network"`
					AccessConfigs []struct{ NatIP string `json:"natIP"` } `json:"accessConfigs"`
				} `json:"networkInterfaces"`
				ServiceAccounts []struct { Email string `json:"email"` } `json:"serviceAccounts"`
			} `json:"instances"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, gcpPageURL(baseURL, "pageToken", pageTok), &resp); err != nil { return nil, err }
	for _, zone := range resp.Items {
		for _, vm := range zone.Instances {
			if vm.Status != "RUNNING" { continue }
			v := vmBlast{
				name:     vm.Name,
				fullName: vm.SelfLink,
				zone:     shortResourceName(vm.Zone),
				status:   vm.Status,
			}
			for _, sa := range vm.ServiceAccounts { v.serviceAccounts = append(v.serviceAccounts, sa.Email) }
			for _, ni := range vm.NetworkInterfaces {
				v.network = ni.Network
				for _, ac := range ni.AccessConfigs { if ac.NatIP != "" { v.publicIP = ac.NatIP } }
			}
			vms = append(vms, v)
		}
	}
	if resp.NextPageToken == "" { break }
	pageTok = resp.NextPageToken
	}
	return vms, nil
}

type iamBinding struct { role string; members []string }

func fetchIAMForBlast(ctx context.Context, token, projectID string) ([]iamBinding, error) {
	url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:getIamPolicy", projectID)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("getIamPolicy: HTTP %d", resp.StatusCode)
	}
	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	json.NewDecoder(resp.Body).Decode(&policy)
	bindings := make([]iamBinding, len(policy.Bindings))
	for i, b := range policy.Bindings { bindings[i] = iamBinding{role: b.Role, members: b.Members} }
	return bindings, nil
}

type bucketBlast struct { name string; isPublic bool }

func fetchBucketsForBlast(ctx context.Context, token, projectID string) ([]bucketBlast, error) {
	baseURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&projection=full&maxResults=200", projectID)
	var buckets []bucketBlast
	pageTok := ""
	for page := 0; page < blastMaxPages; page++ {
		var resp struct {
			NextPageToken string `json:"nextPageToken"`
			Items []struct {
				Name string `json:"name"`
				Acl  []struct{ Entity string `json:"entity"` } `json:"acl"`
			} `json:"items"`
		}
		if err := gcpCSPMGet(ctx, token, gcpPageURL(baseURL, "pageToken", pageTok), &resp); err != nil { return buckets, err }
		for _, b := range resp.Items {
			bucket := bucketBlast{name: b.Name}
			for _, acl := range b.Acl {
				if acl.Entity == "allUsers" || acl.Entity == "allAuthenticatedUsers" { bucket.isPublic = true }
			}
			buckets = append(buckets, bucket)
		}
		if resp.NextPageToken == "" { break }
		pageTok = resp.NextPageToken
	}
	return buckets, nil
}

type firewallBlast struct {
	name, network  string
	ports          []string
	openToInternet bool
	hasCriticalPort bool
}

func fetchFirewallsForBlast(ctx context.Context, token, projectID string) ([]firewallBlast, error) {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls", projectID)
	var resp struct {
		Items []struct {
			Name         string   `json:"name"`
			Network      string   `json:"network"`
			Direction    string   `json:"direction"`
			Disabled     bool     `json:"disabled"`
			SourceRanges []string `json:"sourceRanges"`
			Allowed      []struct {
				IPProtocol string   `json:"IPProtocol"`
				Ports      []string `json:"ports"`
			} `json:"allowed"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil { return nil, err }
	criticalPorts := map[string]bool{"22": true, "3389": true, "23": true, "3306": true, "5432": true}
	var fws []firewallBlast
	for _, fw := range resp.Items {
		if fw.Disabled || fw.Direction != "INGRESS" { continue }
		openToInternet := false
		for _, r := range fw.SourceRanges { if r == "0.0.0.0/0" || r == "::/0" { openToInternet = true } }
		if !openToInternet { continue }
		f := firewallBlast{name: fw.Name, network: fw.Network, openToInternet: true}
		for _, allow := range fw.Allowed {
			if allow.IPProtocol == "all" { f.hasCriticalPort = true; f.ports = append(f.ports, "all") }
			for _, p := range allow.Ports {
				f.ports = append(f.ports, p)
				if criticalPorts[p] { f.hasCriticalPort = true }
			}
		}
		fws = append(fws, f)
	}
	return fws, nil
}

type sqlBlast struct { name, version string; publicIP, openToAll bool }

func fetchSQLForBlast(ctx context.Context, token, projectID string) ([]sqlBlast, error) {
	url := fmt.Sprintf("https://sqladmin.googleapis.com/sql/v1beta4/projects/%s/instances", projectID)
	var resp struct {
		Items []struct {
			Name            string `json:"name"`
			DatabaseVersion string `json:"databaseVersion"`
			Settings        struct {
				IpConfiguration struct {
					Ipv4Enabled        bool `json:"ipv4Enabled"`
					AuthorizedNetworks []struct{ Value string `json:"value"` } `json:"authorizedNetworks"`
				} `json:"ipConfiguration"`
			} `json:"settings"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil { return nil, err }
	var sqls []sqlBlast
	for _, s := range resp.Items {
		sql := sqlBlast{name: s.Name, version: s.DatabaseVersion, publicIP: s.Settings.IpConfiguration.Ipv4Enabled}
		for _, net := range s.Settings.IpConfiguration.AuthorizedNetworks {
			if net.Value == "0.0.0.0/0" { sql.openToAll = true }
		}
		sqls = append(sqls, sql)
	}
	return sqls, nil
}

func fetchSecretsForBlast(ctx context.Context, token, projectID string) ([]string, error) {
	baseURL := fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets?pageSize=200", projectID)
	var names []string
	pageTok := ""
	for page := 0; page < blastMaxPages; page++ {
		var resp struct {
			NextPageToken string `json:"nextPageToken"`
			Secrets []struct{ Name string `json:"name"` } `json:"secrets"`
		}
		if err := gcpCSPMGet(ctx, token, gcpPageURL(baseURL, "pageToken", pageTok), &resp); err != nil { return names, err }
		for _, s := range resp.Secrets { names = append(names, s.Name) }
		if resp.NextPageToken == "" { break }
		pageTok = resp.NextPageToken
	}
	return names, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func sevRank(s string) int {
	switch s { case "critical": return 4; case "high": return 3; case "medium": return 2; case "low": return 1 }
	return 0
}
func maxSev(a, b string) string { if sevRank(a) >= sevRank(b) { return a }; return b }

// gcpImpersonationRoles let a principal act as, mint tokens for, or create keys
// for service accounts. Granted at project level they reach every SA in the
// project, which is the main GCP lateral-movement path (G-42).
var gcpImpersonationRoles = map[string]bool{
	"roles/iam.serviceaccountuser":         true,
	"roles/iam.serviceaccounttokencreator": true,
	"roles/iam.serviceaccountkeyadmin":     true,
	"roles/iam.serviceaccountadmin":        true,
	"roles/iam.workloadidentityuser":       true,
	"roles/iam.serviceaccountopenidtokencreator": true,
}

func isImpersonationRole(role string) bool { return gcpImpersonationRoles[strings.ToLower(role)] }

func iamRoleRisk(role string) string {
	if isImpersonationRole(role) {
		return "high"
	}
	switch role {
	case "roles/owner", "roles/editor", "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin":
		return "critical"
	case "roles/compute.admin", "roles/storage.admin", "roles/cloudsql.admin", "roles/secretmanager.admin":
		return "high"
	case "roles/viewer", "roles/browser":
		return "low"
	}
	lr := strings.ToLower(role)
	if strings.Contains(lr, "admin") { return "high" }
	if strings.HasPrefix(lr, "roles/cloudfunctions.developer") || strings.HasPrefix(lr, "roles/run.developer") ||
		strings.HasPrefix(lr, "roles/compute.instanceadmin") || strings.HasPrefix(lr, "roles/iam.roleadmin") {
		return "high"
	}
	return "medium"
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

func handleRunBlastRadius(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := parseID(r.PathValue("id"))
		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil { writeJSON(w, 404, map[string]string{"error": "connector not found"}); return }

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()

		if conn.Provider == "aws" {
			handleRunAWSBlast(db, id, conn, w, r)
			return
		}

		if conn.Provider == "azure" {
			tenantID     := conn.Credentials["tenant_id"]
			clientID     := conn.Credentials["client_id"]
			clientSecret := conn.Credentials["client_secret"]

			var azCSPM *AzureCSPMResult
			if val, err := db.GetSetting(r.Context(), fmt.Sprintf("cspm:azure:%d", id)); err == nil && val != "" {
				azCSPM = &AzureCSPMResult{}
				json.Unmarshal([]byte(val), azCSPM)
			}
			result, err := RunAzureBlastRadiusForConnector(ctx, tenantID, clientID, clientSecret, conn.Credentials["subscription_id"], conn.AccountID, azCSPM, id)
			if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
			data, _ := json.Marshal(result)
			db.SetSetting(r.Context(), fmt.Sprintf("blast:azure:%d", id), string(data))
			writeJSON(w, 200, result)
			return
		}

		var cspm *CSPMResult
		if val, err := db.GetSetting(r.Context(), fmt.Sprintf("cspm:gcp:%d", id)); err == nil && val != "" {
			cspm = &CSPMResult{}
			json.Unmarshal([]byte(val), cspm)
		}

		result, err := RunGCPBlastRadiusForConnector(ctx, conn.Credentials, conn.AccountID, cspm, id)
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }

		data, _ := json.Marshal(result)
		db.SetSetting(r.Context(), fmt.Sprintf("blast:gcp:%d", id), string(data))
		writeJSON(w, 200, result)
	}
}

func handleGetBlastRadius(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := parseID(r.PathValue("id"))
		// Try provider-aware key
		provider := "gcp"
		if conn, cerr := db.GetCloudConnectorRaw(r.Context(), id); cerr == nil && (conn.Provider == "azure" || conn.Provider == "aws") {
			provider = conn.Provider
		}
		val, err := db.GetSetting(r.Context(), fmt.Sprintf("blast:%s:%d", provider, id))
		if err != nil || val == "" {
			writeJSON(w, 200, map[string]interface{}{"nodes": []interface{}{}, "edges": []interface{}{}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(val))
	}
}

func parseID(s string) (int64, error) {
	var id int64
	_, err := fmt.Sscan(s, &id)
	return id, err
}
