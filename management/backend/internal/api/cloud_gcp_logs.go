package api

// cloud_gcp_logs.go — Extended GCP log source ingestion.
// VPC Flow Logs → cloud.gcp_vpc_flow
// Cloud DNS Logs → cloud.gcp_dns
// Cloud IDS Logs → cloud.gcp_ids

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// gcpLogEntries pages through entries:list (G-03). pageSize is the per-page
// size; total results are bounded so one noisy log can't stall a sync.
func gcpLogEntries(ctx context.Context, token, projectID, filter string, pageSize int) ([]gcpLogEntry, error) {
	const maxPages = 10
	// G-04: the logging read quota is per request, not per entry, so ask for
	// the maximum page size to use as few requests as possible.
	pageSize = 1000
	var all []gcpLogEntry
	pageToken := ""
	for page := 0; page < maxPages; page++ {
		payload := map[string]interface{}{
			"resourceNames": []string{"projects/" + projectID},
			"filter":        filter,
			"orderBy":       "timestamp desc",
			"pageSize":      pageSize,
		}
		if pageToken != "" {
			payload["pageToken"] = pageToken
		}
		body, _ := json.Marshal(payload)
		var resp *http.Response
		var respBody []byte
		for attempt := 0; ; attempt++ {
			req, err := http.NewRequestWithContext(ctx, "POST",
				"https://logging.googleapis.com/v2/entries:list",
				strings.NewReader(string(body)))
			if err != nil {
				return all, err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				return all, err
			}
			respBody, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			// G-04: honour quota errors (429) and transient 503 with Retry-After.
			if (resp.StatusCode == 429 || resp.StatusCode == 503) && attempt < 4 {
				wait := gcpRetryAfter(resp.Header.Get("Retry-After"), attempt)
				select {
				case <-ctx.Done():
					return all, ctx.Err()
				case <-time.After(wait):
				}
				continue
			}
			break
		}
		if resp.StatusCode == 403 {
			return all, fmt.Errorf("permission denied (403)")
		}
		if resp.StatusCode == 404 {
			return all, fmt.Errorf("not found (404)")
		}
		if resp.StatusCode != 200 {
			return all, fmt.Errorf("logging API %d: %s", resp.StatusCode, string(respBody)[:minInt(200, len(respBody))])
		}
		var result struct {
			Entries       []gcpLogEntry `json:"entries"`
			NextPageToken string        `json:"nextPageToken"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return all, err
		}
		all = append(all, result.Entries...)
		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
	}
	return all, nil
}

func pullGCPVPCFlowLogs(ctx context.Context, token, projectID string, since time.Time) ([]gcpLogEntry, error) {
	filter := fmt.Sprintf("logName=\"projects/%s/logs/compute.googleapis.com%%2Fvpc_flows\" AND timestamp>=\"%s\"",
		projectID, since.UTC().Format(time.RFC3339))
	return gcpLogEntries(ctx, token, projectID, filter, 500)
}

func vpcFlowToCloudEvent(e gcpLogEntry, connectorID int64) CloudEvent {
	var flow struct {
		Connection struct {
			SrcIP   string      `json:"src_ip"`
			DstIP   string      `json:"dest_ip"`
			SrcPort int         `json:"src_port"`
			DstPort int         `json:"dest_port"`
			Proto   interface{} `json:"protocol"` // number in real logs, string in some exports
		} `json:"connection"`
		BytesSent   int64  `json:"bytes_sent"`
		Disposition string `json:"disposition"`
		Reporter    string `json:"reporter"`
	}
	if len(e.JSONPayload) > 0 {
		json.Unmarshal(e.JSONPayload, &flow)
	}
	sev := cloudSevInfo
	if strings.EqualFold(flow.Disposition, "DENIED") {
		sev = cloudSevMedium
	}
	host := e.Resource.Labels["project_id"]
	if s := e.Resource.Labels["subnetwork_id"]; s != "" {
		host = s
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"source": "gcp_vpc_flow", "connector_id": connectorID, "insert_id": e.InsertID,
		"log_name": e.LogName, "json_payload": e.JSONPayload, "resource": e.Resource,
		"disposition": flow.Disposition, "bytes_sent": flow.BytesSent, "reporter": flow.Reporter,
		"src_ip": flow.Connection.SrcIP, "dst_ip": flow.Connection.DstIP,
		"src_port": flow.Connection.SrcPort, "dst_port": flow.Connection.DstPort, "proto": flow.Connection.Proto,
	})
	return CloudEvent{
		ID: e.InsertID, Time: e.Timestamp,
		AgentID: fmt.Sprintf("gcp-vpcflow-%d", connectorID), Host: host, OS: "gcp",
		EventType: "cloud.gcp_vpc_flow", Severity: sev, Source: "gcp_vpc_flow",
		SrcIP: flow.Connection.SrcIP, DstIP: flow.Connection.DstIP,
		DstPort: flow.Connection.DstPort, Proto: protoName(flow.Connection.Proto), Raw: raw,
	}
}

func pullGCPDNSLogs(ctx context.Context, token, projectID string, since time.Time) ([]gcpLogEntry, error) {
	filter := fmt.Sprintf("logName=\"projects/%s/logs/dns.googleapis.com%%2Fdns_queries\" AND timestamp>=\"%s\"",
		projectID, since.UTC().Format(time.RFC3339))
	return gcpLogEntries(ctx, token, projectID, filter, 500)
}

func dnsLogToCloudEvent(e gcpLogEntry, connectorID int64) CloudEvent {
	var dns struct {
		QueryName    string `json:"queryName"`
		QueryType    string `json:"queryType"`
		ResponseCode string `json:"responseCode"`
		SourceIP     string `json:"sourceIP"`
	}
	if len(e.JSONPayload) > 0 {
		json.Unmarshal(e.JSONPayload, &dns)
	}
	host := e.Resource.Labels["project_id"]
	raw, _ := json.Marshal(map[string]interface{}{
		"source": "gcp_dns", "connector_id": connectorID, "insert_id": e.InsertID,
		"query_name": dns.QueryName, "query_type": dns.QueryType,
		"response_code": dns.ResponseCode, "src_ip": dns.SourceIP,
		"json_payload": e.JSONPayload, "resource": e.Resource,
	})
	return CloudEvent{
		ID: e.InsertID, Time: e.Timestamp,
		AgentID: fmt.Sprintf("gcp-dns-%d", connectorID), Host: host, OS: "gcp",
		EventType: "cloud.gcp_dns", Severity: cloudSevInfo, Source: "gcp_dns",
		SrcIP: dns.SourceIP, DstIP: strings.TrimSuffix(strings.ToLower(dns.QueryName), "."),
		Proto: "dns", Raw: raw,
	}
}

func pullGCPIDSLogs(ctx context.Context, token, projectID string, since time.Time) ([]gcpLogEntry, error) {
	filter := fmt.Sprintf(
		"logName=(\"projects/%s/logs/ids.googleapis.com%%2Fthreat\" OR \"projects/%s/logs/ids.googleapis.com%%2Ftraffic\") AND timestamp>=\"%s\"",
		projectID, projectID, since.UTC().Format(time.RFC3339))
	return gcpLogEntries(ctx, token, projectID, filter, 200)
}

func idsLogToCloudEvent(e gcpLogEntry, connectorID int64) CloudEvent {
	var ids struct {
		ThreatID  string `json:"threat_id"`
		Name      string `json:"name"`
		Type      string `json:"type"`
		Category  string `json:"category"`
		Severity  string `json:"severity"`
		Direction string `json:"direction"`
		SourceIP  string `json:"source_ip_address"`
		DestIP    string `json:"destination_ip_address"`
		Details   string `json:"details"`
	}
	if len(e.JSONPayload) > 0 {
		json.Unmarshal(e.JSONPayload, &ids)
	}
	sevMap := map[string]int{
		"CRITICAL": cloudSevCritical, "HIGH": cloudSevHigh,
		"MEDIUM": cloudSevMedium, "LOW": cloudSevInfo,
	}
	sev := cloudSevMedium
	if s, ok := sevMap[strings.ToUpper(ids.Severity)]; ok {
		sev = s
	}
	host := e.Resource.Labels["project_id"]
	raw, _ := json.Marshal(map[string]interface{}{
		"source": "gcp_ids", "connector_id": connectorID, "insert_id": e.InsertID,
		"threat_id": ids.ThreatID, "threat_name": ids.Name, "threat_type": ids.Type,
		"category": ids.Category, "severity": ids.Severity, "direction": ids.Direction,
		"src_ip": ids.SourceIP, "dst_ip": ids.DestIP, "details": ids.Details,
		"json_payload": e.JSONPayload, "resource": e.Resource,
	})
	return CloudEvent{
		ID: e.InsertID, Time: e.Timestamp,
		AgentID: fmt.Sprintf("gcp-ids-%d", connectorID), Host: host, OS: "gcp",
		EventType: "cloud.gcp_ids", Severity: sev, Source: "gcp_ids",
		SrcIP: ids.SourceIP, Raw: raw,
	}
}

func syncGCPExtendedLogs(ctx context.Context, conn *store.CloudConnector, db *store.DB, eventDB *store.DB, logger *slog.Logger) int {
	saJSON := conn.Credentials["service_account"]
	projectID := firstGCPProject(conn.Credentials["project_id"])
	if saJSON == "" {
		return 0
	}
	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return 0
	}
	if projectID == "" {
		projectID = sa.ProjectID
	}
	if projectID == "" {
		return 0
	}
	token, err := getGCPToken(ctx, sa)
	if err != nil {
		return 0
	}
	since := time.Now().UTC().Add(-10 * time.Minute)
	if conn.LastSync != nil {
		since = conn.LastSync.Add(-2 * time.Minute)
	}
	total := 0
	type logPuller struct {
		name    string
		entries func() ([]gcpLogEntry, error)
		convert func(gcpLogEntry, int64) CloudEvent
	}
	pullers := []logPuller{
		{"vpc_flow", func() ([]gcpLogEntry, error) { return pullGCPVPCFlowLogs(ctx, token, projectID, since) }, vpcFlowToCloudEvent},
		{"dns", func() ([]gcpLogEntry, error) { return pullGCPDNSLogs(ctx, token, projectID, since) }, dnsLogToCloudEvent},
		{"ids", func() ([]gcpLogEntry, error) { return pullGCPIDSLogs(ctx, token, projectID, since) }, idsLogToCloudEvent},
		{"cloud_run", func() ([]gcpLogEntry, error) { return pullGCPCloudRunLogs(ctx, token, projectID, since) }, cloudRunToCloudEvent},
		{"policy_denied", func() ([]gcpLogEntry, error) { return pullGCPPolicyDeniedLogs(ctx, token, projectID, since) }, policyDeniedToCloudEvent},
		{"lb_armor", func() ([]gcpLogEntry, error) { return pullGCPArmorLogs(ctx, token, projectID, since) }, armorToCloudEvent},
		{"gke_audit", func() ([]gcpLogEntry, error) { return pullGCPGKEAuditLogs(ctx, token, projectID, since) }, gkeAuditToCloudEvent},
	}
	for _, p := range pullers {
		entries, err := p.entries()
		if err != nil {
			logger.Warn("gcp extended: source unavailable", "source", p.name, "project", projectID, "err", err)
			st := "error"
			if strings.Contains(err.Error(), "403") {
				st = "permission_missing"
			} else if strings.Contains(err.Error(), "404") {
				st = "not_enabled"
			}
			recordSourceStatus(conn.ID, "gcp_"+p.name, st, err.Error())
			continue
		}
		recordSourceStatus(conn.ID, "gcp_"+p.name, "ok", "")
		if len(entries) == 0 {
			continue
		}
		evs := make([]CloudEvent, 0, len(entries))
		for _, e := range entries {
			evs = append(evs, p.convert(e, conn.ID))
		}
		n, _ := ingestCloudEvents(ctx, eventDB, evs)
		total += n
		logger.Info("gcp extended: logs ingested", "source", p.name, "project", projectID, "count", n)
	}

	// G-11: SCC threat detections as real-time-ish events (every sync).
	sccEvents, sccErr := pullSCCThreatEvents(ctx, token, projectID, conn.ID)
	if sccErr != nil {
		st := "error"
		if strings.HasPrefix(sccErr.Error(), "scc_unavailable:") {
			st = "not_enabled"
		}
		recordSourceStatus(conn.ID, "gcp_scc", st, sccErr.Error())
	} else {
		recordSourceStatus(conn.ID, "gcp_scc", "ok", "")
		if len(sccEvents) > 0 {
			n, _ := ingestCloudEvents(ctx, eventDB, sccEvents)
			total += n
			logger.Info("gcp extended: SCC threat findings ingested", "project", projectID, "count", n)
		}
	}
	return total
}

// ── Cloud Run request logs ────────────────────────────────────────────────────
// Captures HTTP request logs from Cloud Run services.
// Useful for detecting unusual invocation patterns, error spikes, and probing.
func pullGCPCloudRunLogs(ctx context.Context, token, projectID string, since time.Time) ([]gcpLogEntry, error) {
	filter := fmt.Sprintf(
		"logName=\"projects/%s/logs/run.googleapis.com%%2Frequests\" AND timestamp>=\"%s\"",
		projectID, since.UTC().Format(time.RFC3339))
	return gcpLogEntries(ctx, token, projectID, filter, 500)
}

func cloudRunToCloudEvent(e gcpLogEntry, connectorID int64) CloudEvent {
	var req struct {
		RequestMethod string `json:"requestMethod"`
		RequestURL    string `json:"requestUrl"`
		Status        int    `json:"status"`
		RemoteIP      string `json:"remoteIp"`
		UserAgent     string `json:"userAgent"`
		Latency       string `json:"latency"`
		ResponseSize  string `json:"responseSize"`
	}
	if len(e.JSONPayload) > 0 {
		json.Unmarshal(e.JSONPayload, &req)
	}

	sev := cloudSevInfo
	if req.Status >= 500 {
		sev = cloudSevMedium
	}
	if req.Status == 401 || req.Status == 403 {
		sev = cloudSevMedium
	}

	// Extract service name from log name: projects/p/logs/run.googleapis.com%2Frequests
	// Resource labels contain service name
	serviceName := e.Resource.Labels["service_name"]
	if serviceName == "" {
		serviceName = e.Resource.Labels["configuration_name"]
	}

	host := e.Resource.Labels["project_id"]
	if serviceName != "" {
		host = serviceName
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source": "gcp_cloud_run", "connector_id": connectorID,
		"insert_id": e.InsertID, "log_name": e.LogName,
		"service_name": serviceName, "method": req.RequestMethod,
		"url": req.RequestURL, "status": req.Status,
		"remote_ip": req.RemoteIP, "user_agent": req.UserAgent,
		"latency": req.Latency, "response_size": req.ResponseSize,
		"resource": e.Resource,
	})

	return CloudEvent{
		ID:        e.InsertID,
		Time:      e.Timestamp,
		AgentID:   fmt.Sprintf("gcp-cloudrun-%d", connectorID),
		Host:      host,
		OS:        "gcp",
		EventType: "cloud.gcp_cloud_run",
		Severity:  sev,
		Source:    "gcp_cloud_run",
		SrcIP:     req.RemoteIP,
		Raw:       raw,
	}
}

// ── GKE Kubernetes audit logs ─────────────────────────────────────────────────
// Captures Kubernetes API server audit events from GKE clusters.
// These are distinct from GCP Cloud Audit Logs — they record kubectl commands,
// pod creation, RBAC changes, exec into pods, and other k8s-level operations.
func pullGCPGKEAuditLogs(ctx context.Context, token, projectID string, since time.Time) ([]gcpLogEntry, error) {
	// GKE audit logs appear in two log names depending on cluster config
	filter := fmt.Sprintf(
		`(logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" OR `+
			`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access") `+
			`AND resource.type="k8s_cluster" AND timestamp>="%s"`,
		projectID, projectID, since.UTC().Format(time.RFC3339))
	return gcpLogEntries(ctx, token, projectID, filter, 500)
}

func gkeAuditToCloudEvent(e gcpLogEntry, connectorID int64) CloudEvent {
	// GKE audit logs use protoPayload like standard GCP audit logs
	var proto struct {
		MethodName         string `json:"methodName"`
		ResourceName       string `json:"resourceName"`
		ServiceName        string `json:"serviceName"`
		AuthenticationInfo struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
		RequestMetadata struct {
			CallerIP string `json:"callerIp"`
		} `json:"requestMetadata"`
		Status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
		Request json.RawMessage `json:"request"`
	}
	if len(e.ProtoPayload) > 0 {
		json.Unmarshal(e.ProtoPayload, &proto)
	}
	// G-10: derive structured flags from the request body so rules match
	// on fields rather than substring-searching the whole raw blob.
	reqLower := strings.ToLower(string(proto.Request))
	reqCompact := strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(reqLower)
	privileged := strings.Contains(reqCompact, `"privileged":true`)
	clusterAdminBinding := strings.Contains(reqCompact, `"name":"cluster-admin"`)

	sev := cloudSevInfo
	// Escalate severity for sensitive k8s operations
	method := strings.ToLower(proto.MethodName)
	if strings.Contains(method, "exec") || strings.Contains(method, "portforward") {
		sev = cloudSevMedium // exec into pod is always noteworthy
	}
	if strings.Contains(method, "clusterrolebinding") || strings.Contains(method, "rolebinding") {
		sev = cloudSevMedium
	}
	if strings.Contains(e.Resource.Labels["cluster_name"], "") && proto.Status.Code != 0 {
		sev = cloudSevMedium // any k8s API error worth tracking
	}

	clusterName := e.Resource.Labels["cluster_name"]
	host := e.Resource.Labels["project_id"]
	if clusterName != "" {
		host = clusterName
	}

	principal := proto.AuthenticationInfo.PrincipalEmail
	srcIP := proto.RequestMetadata.CallerIP

	raw, _ := json.Marshal(map[string]interface{}{
		"source": "gcp_gke_audit", "connector_id": connectorID,
		"insert_id": e.InsertID, "log_name": e.LogName,
		"method_name":           proto.MethodName,
		"resource_name":         proto.ResourceName,
		"service_name":          proto.ServiceName,
		"principal":             principal,
		"caller_ip":             srcIP,
		"status_code":           proto.Status.Code,
		"status_msg":            proto.Status.Message,
		"privileged":            privileged,
		"cluster_admin_binding": clusterAdminBinding,
		"cluster":               clusterName,
		"resource":              e.Resource,
	})

	return CloudEvent{
		ID:        e.InsertID,
		Time:      e.Timestamp,
		AgentID:   fmt.Sprintf("gcp-gkeaudit-%d", connectorID),
		Host:      host,
		OS:        "gcp",
		EventType: "cloud.gcp_gke_audit",
		Severity:  sev,
		Source:    "gcp_gke_audit",
		Username:  principal,
		SrcIP:     srcIP,
		Raw:       raw,
	}
}

// protoName maps an IP protocol (number or string, as VPC Flow Logs report
// it) to a name.
func protoName(v interface{}) string {
	n := -1
	switch t := v.(type) {
	case float64:
		n = int(t)
	case string:
		if t == "" {
			return ""
		}
		if i, err := strconv.Atoi(t); err == nil {
			n = i
		} else {
			return strings.ToLower(t)
		}
	default:
		return ""
	}
	switch n {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return strconv.Itoa(n)
}

// gcpRetryAfter returns the wait before retrying: the server's Retry-After
// (seconds) when given, otherwise exponential backoff; capped at 30s.
func gcpRetryAfter(h string, attempt int) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n > 0 {
		if n > 30 {
			n = 30
		}
		return time.Duration(n) * time.Second
	}
	d := time.Duration(1<<uint(attempt)) * 2 * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// G-15: the cloudaudit "policy" log records requests blocked by VPC Service
// Controls and organization-policy constraints.
func pullGCPPolicyDeniedLogs(ctx context.Context, token, projectID string, since time.Time) ([]gcpLogEntry, error) {
	filter := fmt.Sprintf("logName=\"projects/%s/logs/cloudaudit.googleapis.com%%2Fpolicy\" AND timestamp>=\"%s\"",
		projectID, since.UTC().Format(time.RFC3339))
	return gcpLogEntries(ctx, token, projectID, filter, 500)
}

func policyDeniedToCloudEvent(e gcpLogEntry, connectorID int64) CloudEvent {
	var proto struct {
		MethodName         string `json:"methodName"`
		ResourceName       string `json:"resourceName"`
		ServiceName        string `json:"serviceName"`
		AuthenticationInfo struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
		RequestMetadata struct {
			CallerIP string `json:"callerIp"`
		} `json:"requestMetadata"`
		Metadata struct {
			ViolationReason string          `json:"violationReason"`
			SecurityPolicy  string          `json:"securityPolicyInfo"`
			VPCSC           json.RawMessage `json:"vpcServiceControlsUniqueId"`
		} `json:"metadata"`
	}
	if len(e.ProtoPayload) > 0 {
		json.Unmarshal(e.ProtoPayload, &proto)
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"source": "gcp_policy_denied", "connector_id": connectorID, "insert_id": e.InsertID,
		"log_name": e.LogName, "method": proto.MethodName, "service": proto.ServiceName,
		"resource": proto.ResourceName, "principal": proto.AuthenticationInfo.PrincipalEmail,
		"caller_ip": proto.RequestMetadata.CallerIP, "violation_reason": proto.Metadata.ViolationReason,
		"proto_payload": e.ProtoPayload,
	})
	return CloudEvent{
		ID: e.InsertID, Time: e.Timestamp, AgentID: fmt.Sprintf("gcp-policy-%d", connectorID),
		Host: e.Resource.Labels["project_id"], OS: "gcp", EventType: "cloud.gcp_policy_denied",
		Severity: cloudSevMedium, Source: "gcp_policy_denied", Username: proto.AuthenticationInfo.PrincipalEmail,
		SrcIP: proto.RequestMetadata.CallerIP, Raw: raw,
	}
}

var gcpPolicySignatures = []ThreatSig{
	{
		ID: "C-GCP-PLC-001", Name: "GCP: Request Blocked by VPC Service Controls / Org Policy",
		Description: "A request was denied by a VPC Service Controls perimeter or an organization-policy constraint. Repeated denials can indicate data-exfiltration attempts from outside the perimeter or a compromised credential probing protected services.",
		Severity:    3, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool { return ev.EventType == "cloud.gcp_policy_denied" },
	},
}

// G-15: HTTP(S) load-balancer requests that Cloud Armor denied or that a
// preview rule would have denied. Allowed traffic is deliberately not pulled.
func pullGCPArmorLogs(ctx context.Context, token, projectID string, since time.Time) ([]gcpLogEntry, error) {
	filter := fmt.Sprintf("resource.type=\"http_load_balancer\" AND (jsonPayload.enforcedSecurityPolicy.outcome=\"DENY\" OR jsonPayload.previewSecurityPolicy.outcome=\"DENY\") AND timestamp>=\"%s\"",
		since.UTC().Format(time.RFC3339))
	return gcpLogEntries(ctx, token, projectID, filter, 500)
}

func armorToCloudEvent(e gcpLogEntry, connectorID int64) CloudEvent {
	var lb struct {
		StatusDetails string `json:"statusDetails"`
		Enforced      struct {
			Name             string `json:"name"`
			ConfiguredAction string `json:"configuredAction"`
			Outcome          string `json:"outcome"`
		} `json:"enforcedSecurityPolicy"`
		Preview struct {
			Name    string `json:"name"`
			Outcome string `json:"outcome"`
		} `json:"previewSecurityPolicy"`
	}
	var req struct {
		RemoteIP   string `json:"remoteIp"`
		RequestURL string `json:"requestUrl"`
		Method     string `json:"requestMethod"`
		UserAgent  string `json:"userAgent"`
		Status     int    `json:"status"`
	}
	if len(e.JSONPayload) > 0 {
		json.Unmarshal(e.JSONPayload, &lb)
	}
	if len(e.HTTPRequest) > 0 {
		json.Unmarshal(e.HTTPRequest, &req)
	}
	policy, enforced := lb.Enforced.Name, lb.Enforced.Outcome == "DENY"
	if !enforced {
		policy = lb.Preview.Name
	}
	sev := cloudSevMedium
	if !enforced {
		sev = cloudSevInfo
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"source": "gcp_lb_armor", "connector_id": connectorID, "insert_id": e.InsertID,
		"policy": policy, "enforced": enforced, "action": lb.Enforced.ConfiguredAction,
		"remote_ip": req.RemoteIP, "request_url": req.RequestURL, "method": req.Method,
		"user_agent": req.UserAgent, "status": req.Status, "status_details": lb.StatusDetails,
	})
	return CloudEvent{
		ID: e.InsertID, Time: e.Timestamp, AgentID: fmt.Sprintf("gcp-armor-%d", connectorID),
		Host: e.Resource.Labels["url_map_name"], OS: "gcp", EventType: "cloud.gcp_lb_armor",
		Severity: sev, Source: "gcp_lb_armor", SrcIP: req.RemoteIP, Raw: raw,
	}
}
