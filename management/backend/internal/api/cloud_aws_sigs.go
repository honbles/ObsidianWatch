package api

import (
	"regexp"
	"strings"

	"obsidianwatch/management/internal/store"
)

// AW-08: additional AWS CloudTrail detections. Matching is on the compact,
// lower-cased raw JSON emitted by cloudTrailRecordToCloudEvent, with
// failed calls (error_code set) excluded so only effective actions alert.

func awsEvent(ev store.Event, names ...string) (string, bool) {
	if ev.EventType != "cloud.cloudtrail" {
		return "", false
	}
	raw := strings.ToLower(rawStr(ev))
	if !containsAny(raw, `"error_code":""`) && containsAny(raw, `"error_code":"`) {
		return raw, false
	}
	for _, n := range names {
		if strings.Contains(raw, `"event_name":"`+strings.ToLower(n)+`"`) {
			return raw, true
		}
	}
	return raw, false
}

var awsExtraSignatures = []ThreatSig{
	{
		ID: "C-AWS-041", Name: "AWS Console Login Without MFA",
		Description: "Successful console login by an IAM user without MFA.",
		Severity:    3, MITRE: "T1078.004", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw, ok := awsEvent(ev, "ConsoleLogin")
			return ok && strings.Contains(raw, `"mfaused":"no"`) &&
				strings.Contains(raw, `"consolelogin":"success"`)
		},
	},
	{
		ID: "C-AWS-042", Name: "AWS Root Account Activity",
		Description: "API activity performed by the account root user.",
		Severity:    5, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			if ev.EventType != "cloud.cloudtrail" {
				return false
			}
			raw := strings.ToLower(rawStr(ev))
			return strings.Contains(raw, `"type":"root"`) &&
				!strings.Contains(raw, `"event_name":"consolelogin"`) &&
				!strings.Contains(raw, `"read_only":true`)
		},
	},
	{
		ID: "C-AWS-043", Name: "AWS Root Access Key Created",
		Description: "Access key created for the root user.",
		Severity:    5, MITRE: "T1098.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw, ok := awsEvent(ev, "CreateAccessKey")
			return ok && strings.Contains(raw, `"type":"root"`)
		},
	},
	{
		ID: "C-AWS-044", Name: "AWS Login Profile Created or Changed",
		Description: "Console password set or changed for an IAM user (CreateLoginProfile/UpdateLoginProfile) — common persistence step.",
		Severity:    4, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool {
			_, ok := awsEvent(ev, "CreateLoginProfile", "UpdateLoginProfile")
			return ok
		},
	},
	{
		ID: "C-AWS-045", Name: "AWS AdministratorAccess Policy Attached",
		Description: "AdministratorAccess managed policy attached to a user, group or role.",
		Severity:    5, MITRE: "T1098.003", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw, ok := awsEvent(ev, "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy")
			return ok && strings.Contains(raw, "policy/administratoraccess")
		},
	},
	{
		ID: "C-AWS-046", Name: "AWS SSM SendCommand Executed",
		Description: "Remote command executed on instances via SSM — lateral movement / execution path.",
		Severity:    3, MITRE: "T1651", Category: "Execution",
		Match: func(ev store.Event) bool {
			_, ok := awsEvent(ev, "SendCommand", "StartSession")
			return ok && strings.Contains(strings.ToLower(rawStr(ev)), `"event_source":"ssm.amazonaws.com"`)
		},
	},
	{
		ID: "C-AWS-047", Name: "AWS PassRole Privilege Escalation Pattern",
		Description: "Creation of a Lambda/EC2/CloudFormation resource with a privileged role, or a new policy version set as default (PassRole / CreatePolicyVersion escalation).",
		Severity:    4, MITRE: "T1548", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw, ok := awsEvent(ev, "CreatePolicyVersion", "SetDefaultPolicyVersion", "CreateFunction20150331", "RunInstances", "CreateStack")
			if !ok {
				return false
			}
			if strings.Contains(raw, `"event_name":"createpolicyversion"`) {
				return strings.Contains(raw, `"setasdefault":true`)
			}
			return strings.Contains(raw, "administrator") || strings.Contains(raw, "poweruser") || strings.Contains(raw, `"role":"arn:aws:iam::`) && strings.Contains(raw, "admin")
		},
	},
}

var awsEventNameRe = regexp.MustCompile(`"event_name"\s*:\s*"([^"]*)"`)

// awsActionHas (CC-04) reports whether the CloudTrail API action (event_name)
// contains any of the lower-case tokens. It matches ONLY the action field, so
// a user agent, bucket name or request parameter that happens to contain
// "createuser" no longer triggers the rule.
func awsActionHas(ev store.Event, tokens ...string) bool {
	m := awsEventNameRe.FindStringSubmatch(rawStr(ev)) // rawStr is lower-cased
	if m == nil {
		return false
	}
	name := m[1]
	for _, t := range tokens {
		if strings.Contains(name, t) {
			return true
		}
	}
	return false
}

var (
	azureOpRe   = regexp.MustCompile(`"operation_name"\s*:\s*"([^"]*)"`)
	gcpMethodRe = regexp.MustCompile(`"method_name"\s*:\s*"([^"]*)"`)
)

func fieldHas(ev store.Event, re *regexp.Regexp, tokens []string) bool {
	m := re.FindStringSubmatch(rawStr(ev)) // rawStr is lower-cased
	if m == nil {
		return false
	}
	for _, t := range tokens {
		if strings.Contains(m[1], t) {
			return true
		}
	}
	return false
}

// azureOpHas / gcpMethodHas (CC-04): match only the parsed operation / method
// name instead of substring-searching the whole raw JSON.
func azureOpHas(ev store.Event, tokens ...string) bool   { return fieldHas(ev, azureOpRe, tokens) }
func gcpMethodHas(ev store.Event, tokens ...string) bool { return fieldHas(ev, gcpMethodRe, tokens) }
