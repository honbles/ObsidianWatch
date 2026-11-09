package api

import (
	"math"
	"regexp"
	"strings"
)

// DS-05: one shared secret scanner for commit diffs. Provider-specific
// patterns match on their own; generic key/value patterns must pass a
// placeholder + entropy filter. Lines with an ignore marker are skipped, and
// matches are redacted before a patch is stored or sent to AI.

type secretRule struct {
	re      *regexp.Regexp
	generic bool // generic assignment pattern: apply placeholder/entropy filter to group 2
}

var secretRules = []secretRule{
	{regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+]{20,})`), true},
	{regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api_key|apikey|api_secret|token|auth_token|access_token|private_key)\s*[=:]\s*["']([^"'\s]{8,})`), true},
	{regexp.MustCompile(`(?i)(client_secret|client-secret)\s*[=:]\s*["']?([a-zA-Z0-9\-_.~]{32,})`), true},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), false},
	{regexp.MustCompile(`\bgh[pousr]_[a-zA-Z0-9]{36,}\b`), false},
	{regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{50,}\b`), false},
	{regexp.MustCompile(`\bglpat-[a-zA-Z0-9\-_]{20,}\b`), false},
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`), false},
	{regexp.MustCompile(`\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b`), false},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), false},
	{regexp.MustCompile(`\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b`), false},
	{regexp.MustCompile(`\b(?:sk|rk)_live_[a-zA-Z0-9]{24,}\b`), false},
	{regexp.MustCompile(`\bnpm_[a-zA-Z0-9]{36}\b`), false},
	{regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}`), false},
	{regexp.MustCompile(`(?i)\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^\s"'<>:@/]+:[^\s"'<>@]{4,}@`), false},
	{regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}`), false},
	{regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), false},
}

// secretPatterns remains for callers that match on plain strings (paths).
var secretPatterns = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(secretRules))
	for _, r := range secretRules {
		if !r.generic {
			out = append(out, r.re)
		}
	}
	return out
}()

var ignoreMarkers = []string{"ow:ignore", "pragma: allowlist secret", "nosec", "gitleaks:allow", "noqa: secret"}

var placeholderWords = []string{
	"example", "changeme", "change_me", "placeholder", "your_", "your-", "<your", "xxxx", "dummy",
	"sample", "test", "todo", "fixme", "redacted", "replace", "insert", "password", "secret", "token",
	"${", "{{", "%s", "process.env", "os.getenv", "env[", "null", "none", "undefined", "foobar",
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	h := 0.0
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func looksLikeRealSecret(v string) bool {
	lv := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(lv, w) {
			return false
		}
	}
	if strings.Trim(v, v[:1]) == "" { // all the same character
		return false
	}
	return shannonEntropy(v) >= 3.0
}

func hasIgnoreMarker(line string) bool {
	l := strings.ToLower(line)
	for _, m := range ignoreMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// lineHasSecret reports whether a single added diff line likely contains a secret.
func lineHasSecret(line string) bool {
	if hasIgnoreMarker(line) {
		return false
	}
	for _, r := range secretRules {
		m := r.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if r.generic && len(m) >= 3 && !looksLikeRealSecret(m[2]) {
			continue
		}
		return true
	}
	return false
}

// redactSecrets replaces matched secret values so stored diffs and AI prompts
// never contain them.
func redactSecrets(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		for _, r := range secretRules {
			if !r.re.MatchString(line) {
				continue
			}
			line = r.re.ReplaceAllStringFunc(line, func(m string) string {
				if r.generic {
					sub := r.re.FindStringSubmatch(m)
					if len(sub) >= 3 && !looksLikeRealSecret(sub[2]) {
						return m
					}
					return strings.Replace(m, sub[2], "[REDACTED]", 1)
				}
				return "[REDACTED]"
			})
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}
