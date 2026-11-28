package api

import "regexp"

// secretPatternsDef is the pattern set the secrets engine uses for the git
// history pass (secrets that were committed and later removed).
var secretPatternsDef = []struct {
	name    string
	pattern *regexp.Regexp
	sev     string
}{
	{"AWS Access Key", regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), "critical"},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})`), "critical"},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY`), "critical"},
	{"GitHub Token", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}`), "critical"},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}`), "critical"},
	{"Stripe Key", regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`), "critical"},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "high"},
	{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}`), "high"},
	{"Generic Password", regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|api_secret|auth_token|access_token)\s*[=:]\s*["']([^"'\s]{8,})`), "high"},
	{"DB Connection String", regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis|mongodb\+srv)://[^\s"'<>]+:[^\s"'<>@]+@`), "high"},
	{"Generic Token", regexp.MustCompile(`(?i)(token|auth)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{32,})`), "medium"},
	{"IP + Port Hardcoded", regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b`), "low"},
}
