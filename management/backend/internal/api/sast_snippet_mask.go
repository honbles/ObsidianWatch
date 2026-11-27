package api

import (
	"regexp"
	"strings"
)

// Credential findings (hard-coded passwords, keys, tokens) used to keep the matched line as their snippet, so
// the secret itself was stored with the scan, shown in the console, sent to the AI helpers and posted on pull
// requests. Their snippets are now masked: every quoted literal and every unquoted value after a credential-like
// name keeps its first two characters. The mask is idempotent, and findingFingerprint applies it too, so a
// finding stored before masking and the same finding scanned after it share one fingerprint (triage holds).

var credentialCWEs = map[string]bool{"CWE-798": true, "CWE-259": true, "CWE-321": true, "CWE-522": true, "CWE-312": true}

var (
	maskQuotedRe = regexp.MustCompile("([\"'`])([^\"'`]{3,})([\"'`])")
	maskAssignRe = regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_.-]*\s*[:=]\s*)([^\s"'` + "`" + `,;)]{3,})`)
	maskPEMRe    = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[^"'` + "`" + `]*`)
)

func maskValue(v string) string {
	r := []rune(v)
	if len(r) <= 2 {
		return "****"
	}
	return string(r[:2]) + "****"
}

// maskCredentialSnippet hides literal values in a snippet. maskCredentialSnippet(maskCredentialSnippet(s)) ==
// maskCredentialSnippet(s).
func maskCredentialSnippet(s string) string {
	if s == "" {
		return s
	}
	s = maskPEMRe.ReplaceAllString(s, "-----BEGIN PRIVATE KEY-----****")
	s = maskQuotedRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := maskQuotedRe.FindStringSubmatch(m)
		return sub[1] + maskValue(sub[2]) + sub[3]
	})
	return maskAssignRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := maskAssignRe.FindStringSubmatch(m)
		return sub[1] + maskValue(sub[2])
	})
}

// isCredentialFinding reports a finding whose snippet would show a secret.
func isCredentialFinding(f SASTFinding) bool {
	if credentialCWEs[cweID(f.CWE)] {
		return true
	}
	id := strings.ToLower(f.RuleID)
	return strings.HasPrefix(id, "secret-") || strings.Contains(id, "hardcoded") || strings.Contains(id, "secret")
}

// maskFindingSnippets masks the snippets of credential findings in place.
func maskFindingSnippets(fs []SASTFinding) {
	for i := range fs {
		if isCredentialFinding(fs[i]) {
			fs[i].Snippet = maskCredentialSnippet(fs[i].Snippet)
		}
	}
}
