package api

// cloud_gcp_compliance.go — Compliance framework mapping for GCP CSPM findings.
//
// Maps existing CSPMFinding results to formal compliance framework controls:
//   SOC 2 Type II  — Trust Service Criteria (CC6, CC7, CC8, A1)
//   PCI-DSS v4.0   — Requirements 1, 2, 6, 7, 8, 10
//   ISO 27001:2022 — Annex A controls (A.5–A.8)
//   NIST 800-53 R5 — AC, AU, CA, CM, IA, SC, SI families
//
// Usage: call MapToCompliance(cspmResult) after RunGCPCSPM to get a
// ComplianceReport with per-framework pass/fail scores.
// API endpoint: GET /api/v1/cloud-connectors/{id}/compliance

import (
	"fmt"
	"strings"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type ComplianceControl struct {
	ControlID   string `json:"control_id"`   // e.g. "CC6.1", "PCI-7.2", "A.5.15", "AC-2"
	Framework   string `json:"framework"`    // SOC2, PCI-DSS, ISO27001, NIST-800-53
	Title       string `json:"title"`
	Status      string `json:"status"`       // PASS, FAIL, PARTIAL, NOT_APPLICABLE, NOT_ASSESSED
	Reason      string `json:"reason,omitempty"` // why a control is NOT_ASSESSED
	FindingIDs  []string `json:"finding_ids,omitempty"` // CSPM finding IDs that contributed
	Description string `json:"description"`
}

type FrameworkScore struct {
	Framework    string  `json:"framework"`
	Passed       int     `json:"passed"`
	Failed       int     `json:"failed"`
	Partial      int     `json:"partial"`
	NotAssessed  int     `json:"not_assessed"`
	Total        int     `json:"total"`
	ScorePercent float64 `json:"score_percent"`
}

type ComplianceReport struct {
	ConnectorID  int64               `json:"connector_id"`
	ProjectID    string              `json:"project_id"`
	ScannedAt    time.Time           `json:"scanned_at"`
	Controls     []ComplianceControl `json:"controls"`
	Scores       []FrameworkScore    `json:"scores"`
	TotalPassed  int                 `json:"total_passed"`
	TotalFailed  int                 `json:"total_failed"`
	TotalNotAssessed int             `json:"total_not_assessed"`
	// G-37: this is an indicative posture mapping of automated checks to
	// control themes — it is not an attestation of compliance.
	Disclaimer string `json:"disclaimer"`
}

// checkCoverage maps CSPM check names to the finding categories / resource
// types they populate, so a skipped check marks the related controls
// NOT_ASSESSED instead of PASS.
var checkCoverage = map[string][]string{
	"firewall":          {"network", "firewall_rule"},
	"iam":               {"iam", "iam_binding"},
	"storage":           {"storage", "gcs_bucket"},
	"compute":           {"compute", "compute_instance"},
	"sql":               {"sql", "cloud_sql"},
	"audit_logging":     {"logging", "log_sink", "audit_config"},
	"service_accounts":  {"iam", "service_account_key"},
	"kms":               {"kms", "kms_key"},
	"vpc_flow_logs":     {"logging", "network"},
	"dns_logging":       {"logging"},
	"gke":               {"gke_cluster"},
	"bigquery":          {"bigquery_dataset"},
	"secret_manager":    {"secret"},
	"org_policies":      {"org_policy"},
	"cloud_run":         {"cloud_run_service"},
	"artifact_registry": {"artifact_registry"},
	"cloud_functions":   {"cloud_function"},
	"pubsub":            {"pubsub"},
	"org_iam":           {"org_iam_binding"},
	// Azure check names
	"network":            {"network", "nsg"},
	"logging":            {"logging", "diagnostic_setting"},
	"keyvault":           {"kms", "key_vault"},
	"aks":                {"aks_cluster"},
	"defender":           {"defender_plan"},
	"app_service":        {"app_service"},
	"container_registry": {"container_registry"},
	"functions":          {"function_app"},
	"sql_advanced":       {"sql", "sql_server", "sql_database"},
	"entra":              {"entra_tenant"},
}

// ── Control catalogue ─────────────────────────────────────────────────────────
// Each entry defines: which CSPM categories/resource types map to this control,
// and what severity threshold counts as a failure.

type complianceRule struct {
	ControlID   string
	Framework   string
	Title       string
	Description string
	// A finding contributes to this control if it matches ANY of these
	Categories    []string // CSPMFinding.Category values
	ResourceTypes []string // CSPMFinding.ResourceType values (OR with Categories)
	Severities    []string // only findings of these severities count as failures
}

var complianceCatalogue = []complianceRule{
	// ── SOC 2 ─────────────────────────────────────────────────────────────────
	{
		ControlID: "CC6.1", Framework: "SOC2",
		Title:       "Logical and physical access controls — access restriction",
		Description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
		Categories:    []string{"iam"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "CC6.2", Framework: "SOC2",
		Title:       "Logical and physical access controls — prior to issuance of credentials",
		Description: "Prior to issuing system credentials, the entity registers and authorizes new users.",
		Categories:    []string{"iam"},
		ResourceTypes: []string{"service_account_key", "iam_binding"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "CC6.3", Framework: "SOC2",
		Title:       "Logical and physical access controls — removes access when appropriate",
		Description: "The entity authorizes, modifies, or removes access based on changes in job roles.",
		ResourceTypes: []string{"iam_binding", "org_iam_binding", "role_assignment"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "CC6.6", Framework: "SOC2",
		Title:       "Logical and physical access controls — boundary protection",
		Description: "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
		Categories:    []string{"network"},
		ResourceTypes: []string{"firewall_rule", "nsg"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "CC6.7", Framework: "SOC2",
		Title:       "Logical and physical access controls — transmission and movement of information",
		Description: "The entity restricts the transmission, movement, and removal of information to authorized parties.",
		Categories:    []string{"storage", "sql"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "CC6.8", Framework: "SOC2",
		Title:       "Logical and physical access controls — prevents unauthorized software",
		Description: "The entity implements controls to prevent or detect and act upon the introduction of unauthorized software.",
		ResourceTypes: []string{"artifact_registry", "gke_cluster", "cloud_run_service"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "CC7.1", Framework: "SOC2",
		Title:       "System operations — detection of configuration changes",
		Description: "The entity uses detection and monitoring procedures to identify changes to configurations.",
		Categories:    []string{"logging"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "CC7.2", Framework: "SOC2",
		Title:       "System operations — monitors system components for anomalies",
		Description: "The entity monitors system components and the operation of controls to detect anomalies.",
		Categories:    []string{"logging", "compute"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "CC8.1", Framework: "SOC2",
		Title:       "Change management — authorizes, designs, develops/acquires changes",
		Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes.",
		Categories:    []string{"iam"},
		ResourceTypes: []string{"org_policy"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "A1.1", Framework: "SOC2",
		Title:       "Availability — current processing capacity",
		Description: "The entity maintains, monitors, and evaluates current processing capacity and use of system components.",
		ResourceTypes: []string{"cloud_sql", "compute_instance"},
		Severities:    []string{"critical"},
	},

	// ── PCI-DSS v4.0 ──────────────────────────────────────────────────────────
	{
		ControlID: "PCI-1.3", Framework: "PCI-DSS",
		Title:       "Requirement 1.3 — Network access controls restrict inbound/outbound traffic",
		Description: "Restrict inbound and outbound traffic to only that which is necessary for the cardholder data environment.",
		Categories:    []string{"network"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "PCI-2.2", Framework: "PCI-DSS",
		Title:       "Requirement 2.2 — System components configured securely",
		Description: "Develop configuration standards for all system components that address known security vulnerabilities.",
		Categories:    []string{"compute", "sql"},
		ResourceTypes: []string{"compute_instance", "cloud_sql", "gke_cluster"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "PCI-6.3", Framework: "PCI-DSS",
		Title:       "Requirement 6.3 — Security vulnerabilities identified and addressed",
		Description: "Security vulnerabilities are identified and protected against.",
		ResourceTypes: []string{"gke_cluster", "artifact_registry", "cloud_run_service"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "PCI-7.2", Framework: "PCI-DSS",
		Title:       "Requirement 7.2 — Access control system implemented",
		Description: "Access to system components and cardholder data is managed via an access control system.",
		Categories:    []string{"iam"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "PCI-8.2", Framework: "PCI-DSS",
		Title:       "Requirement 8.2 — User identification and authentication managed",
		Description: "All users are assigned a unique ID. Authentication policies prevent use of group/shared accounts.",
		ResourceTypes: []string{"service_account_key", "iam_binding"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "PCI-8.3", Framework: "PCI-DSS",
		Title:       "Requirement 8.3 — User authentication mechanisms including MFA",
		Description: "All individual non-consumer user access to in-scope system components is authenticated with at least one authentication factor.",
		Categories:    []string{"iam"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "PCI-10.2", Framework: "PCI-DSS",
		Title:       "Requirement 10.2 — Audit logs capture all individual user activity",
		Description: "Audit logs capture all individual user access to cardholder data, actions by root/admin, access to audit trails, and invalid access attempts.",
		Categories:    []string{"logging"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "PCI-10.5", Framework: "PCI-DSS",
		Title:       "Requirement 10.5 — Retain audit logs for at least 12 months",
		Description: "Retain audit log history for at least 12 months with at least the most recent three months available for immediate analysis.",
		ResourceTypes: []string{"log_sink", "audit_config"},
		Severities:    []string{"critical", "high", "medium"},
	},

	// ── ISO 27001:2022 ────────────────────────────────────────────────────────
	{
		ControlID: "A.5.15", Framework: "ISO27001",
		Title:       "Access control",
		Description: "Rules to control physical and logical access to information and assets shall be established and implemented.",
		Categories:    []string{"iam"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "A.5.16", Framework: "ISO27001",
		Title:       "Identity management",
		Description: "The full lifecycle of identities shall be managed.",
		ResourceTypes: []string{"service_account_key", "iam_binding", "org_iam_binding"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "A.5.10", Framework: "ISO27001",
		Title:       "Acceptable use of information and assets",
		Description: "Rules for the acceptable use of and procedures for handling information and assets shall be identified, documented, and implemented.",
		Categories:    []string{"storage"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "A.8.15", Framework: "ISO27001",
		Title:       "Logging",
		Description: "Logs that record activities, exceptions, faults, and other relevant events shall be produced, stored, protected, and analysed.",
		Categories:    []string{"logging"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "A.8.20", Framework: "ISO27001",
		Title:       "Networks security",
		Description: "Networks and network devices shall be secured, managed, and controlled to protect information systems and applications.",
		Categories:    []string{"network"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "A.8.24", Framework: "ISO27001",
		Title:       "Use of cryptography",
		Description: "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
		Categories:    []string{"kms"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "A.8.25", Framework: "ISO27001",
		Title:       "Secure development life cycle",
		Description: "Rules for the secure development of software and systems shall be established and applied.",
		ResourceTypes: []string{"artifact_registry", "gke_cluster"},
		Severities:    []string{"critical", "high"},
	},

	// ── NIST 800-53 Rev5 ─────────────────────────────────────────────────────
	{
		ControlID: "AC-2", Framework: "NIST-800-53",
		Title:       "Account Management",
		Description: "Manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
		Categories:    []string{"iam"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "AC-3", Framework: "NIST-800-53",
		Title:       "Access Enforcement",
		Description: "Enforces approved authorizations for logical access to information and system resources.",
		ResourceTypes: []string{"iam_binding", "org_iam_binding", "service_account_key"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "AC-17", Framework: "NIST-800-53",
		Title:       "Remote Access",
		Description: "Establishes and documents usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access.",
		Categories:    []string{"network", "compute"},
		ResourceTypes: []string{"firewall_rule", "compute_instance"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "AU-2", Framework: "NIST-800-53",
		Title:       "Event Logging",
		Description: "Identifies the types of events that the system is capable of logging in support of the audit function.",
		Categories:    []string{"logging"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "AU-9", Framework: "NIST-800-53",
		Title:       "Protection of Audit Information",
		Description: "Protects audit information and audit tools from unauthorized access, modification, and deletion.",
		ResourceTypes: []string{"log_sink", "audit_config"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "CM-6", Framework: "NIST-800-53",
		Title:       "Configuration Settings",
		Description: "Establishes and documents configuration settings for technology products employed within the information system that reflect the most restrictive mode consistent with requirements.",
		Categories:    []string{"compute", "sql", "network"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "IA-5", Framework: "NIST-800-53",
		Title:       "Authenticator Management",
		Description: "Manages information system authenticators by verifying identity prior to distribution, protecting content from unauthorized disclosure, and requiring minimum security safeguards.",
		ResourceTypes: []string{"service_account_key", "kms_key"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "SC-7", Framework: "NIST-800-53",
		Title:       "Boundary Protection",
		Description: "Monitors and controls communications at the external boundary of the system and at key internal boundaries within the system.",
		Categories:    []string{"network"},
		Severities:    []string{"critical", "high"},
	},
	{
		ControlID: "SC-28", Framework: "NIST-800-53",
		Title:       "Protection of Information at Rest",
		Description: "The information system protects the confidentiality and integrity of information at rest.",
		Categories:    []string{"kms", "storage"},
		ResourceTypes: []string{"kms_key", "gcs_bucket", "cloud_sql", "bigquery_dataset"},
		Severities:    []string{"critical", "high", "medium"},
	},
	{
		ControlID: "SI-3", Framework: "NIST-800-53",
		Title:       "Malicious Code Protection",
		Description: "Implements malicious code protection mechanisms at information system entry and exit points.",
		ResourceTypes: []string{"gke_cluster", "artifact_registry", "cloud_run_service"},
		Severities:    []string{"critical", "high"},
	},
}

// ── MapToCompliance maps a CSPMResult to a full compliance report ─────────────

func MapToCompliance(cspm *CSPMResult) *ComplianceReport {
	report := &ComplianceReport{
		ConnectorID: cspm.ConnectorID,
		ProjectID:   cspm.ProjectID,
		ScannedAt:   cspm.ScannedAt,
	}

	report.Disclaimer = "Indicative posture mapping of automated cloud checks to control themes. Not an audit or attestation of compliance; controls marked NOT_ASSESSED had no completed check."

	// Index findings by category and resource type for fast lookup
	failingByCategory     := map[string][]string{} // category → finding IDs
	failingByResourceType := map[string][]string{} // resource_type → finding IDs

	for _, f := range cspm.Findings {
		if f.Status == "suppressed" { continue }
		failingByCategory[f.Category]     = append(failingByCategory[f.Category], f.ID)
		failingByResourceType[f.ResourceType] = append(failingByResourceType[f.ResourceType], f.ID)
	}

	// Controls whose evidence came from a check that did not run.
	skipped := map[string]string{} // category/resource type → reason
	for _, na := range cspm.NotAssessed {
		for _, k := range checkCoverage[na.Check] {
			skipped[k] = na.Check + ": " + na.Reason
		}
	}

	// Evaluate each control
	frameworkCounts := map[string]*FrameworkScore{}

	for _, rule := range complianceCatalogue {
		if _, ok := frameworkCounts[rule.Framework]; !ok {
			frameworkCounts[rule.Framework] = &FrameworkScore{Framework: rule.Framework}
		}
		fs := frameworkCounts[rule.Framework]
		fs.Total++

		// Collect relevant findings for this control
		relevantIDs := map[string]bool{}
		for _, cat := range rule.Categories {
			for _, id := range failingByCategory[cat] {
				relevantIDs[id] = true
			}
		}
		for _, rt := range rule.ResourceTypes {
			for _, id := range failingByResourceType[rt] {
				relevantIDs[id] = true
			}
		}

		// Filter by severity threshold
		matchedIDs := []string{}
		sevSet := map[string]bool{}
		for _, s := range rule.Severities { sevSet[s] = true }

		for _, f := range cspm.Findings {
			if relevantIDs[f.ID] && sevSet[f.Severity] && f.Status != "suppressed" {
				matchedIDs = append(matchedIDs, f.ID)
			}
		}

		status := "PASS"
		reason := ""
		if len(matchedIDs) > 0 {
			status = "FAIL"
			fs.Failed++
		} else {
			// G-37: no finding is only a PASS if every contributing check ran
			// and the control maps to at least one check.
			if len(rule.Categories) == 0 && len(rule.ResourceTypes) == 0 {
				reason = "no automated check maps to this control"
			}
			for _, k := range append(append([]string{}, rule.Categories...), rule.ResourceTypes...) {
				if r, ok := skipped[k]; ok {
					reason = r
					break
				}
			}
			if reason != "" {
				status = "NOT_ASSESSED"
				fs.NotAssessed++
			} else {
				fs.Passed++
			}
		}

		report.Controls = append(report.Controls, ComplianceControl{
			ControlID:   rule.ControlID,
			Framework:   rule.Framework,
			Title:       rule.Title,
			Description: rule.Description,
			Status:      status,
			Reason:      reason,
			FindingIDs:  matchedIDs,
		})
	}

	// Compute scores
	for _, fs := range frameworkCounts {
		// Score over assessed controls only; unassessed ones don't count as passes.
		if assessed := fs.Total - fs.NotAssessed; assessed > 0 {
			fs.ScorePercent = float64(fs.Passed) / float64(assessed) * 100
		}
		report.TotalNotAssessed += fs.NotAssessed
		report.Scores = append(report.Scores, *fs)
		report.TotalPassed += fs.Passed
		report.TotalFailed += fs.Failed
	}

	return report
}

// ComplianceSummary returns a one-line string per framework for logging/alerts.
func ComplianceSummary(r *ComplianceReport) string {
	parts := make([]string, 0, len(r.Scores))
	for _, s := range r.Scores {
		parts = append(parts, fmt.Sprintf("%s: %.0f%% (%d/%d passed, %d not assessed)",
			s.Framework, s.ScorePercent, s.Passed, s.Total, s.NotAssessed))
	}
	return strings.Join(parts, " | ")
}
