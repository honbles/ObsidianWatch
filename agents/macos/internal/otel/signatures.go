package otel

// signatures.go - injection signatures run over request parameter values in the agent. A hit becomes a
// class label ("param.sql-injection") that travels as the exception type of the request's client record,
// so the existing injection rule (A09) counts it with no value ever leaving the host. Patterns are
// deliberately conservative: a hit needs attack syntax, not just a keyword.

import (
	"net/url"
	"regexp"
)

const sigPrefix = "param."

var injectionSigs = []struct {
	class string
	re    *regexp.Regexp
}{
	{"sql-injection", regexp.MustCompile(`(?i)(\bunion\b[\s/*]+(all[\s/*]+)?select\b|\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|['"]\s*(or|and)\s+['"]?[\w]+['"]?\s*=|;\s*(drop|delete|insert|update|alter|truncate)\b|\b(sleep|benchmark|pg_sleep|waitfor\s+delay|extractvalue|updatexml|load_file)\s*\(|--\s*$|/\*.*\*/\s*(or|and|union|select)\b|\binformation_schema\b)`)},
	{"script-injection", regexp.MustCompile(`(?i)(<\s*script\b|<\s*/\s*script|\bon(error|load|click|mouseover|focus)\s*=|javascript\s*:|<\s*(img|svg|iframe|body)\b[^>]*\bon\w+\s*=)`)},
	{"command-injection", regexp.MustCompile(`(?i)([;|&]\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|powershell|cmd)\b|\$\(\s*\w+|` + "`" + `\s*\w+[^` + "`" + `]*` + "`" + `|\b(cmd(\.exe)?\s*/c|/bin/(ba)?sh)\b)`)},
	{"path-traversal", regexp.MustCompile(`(?i)(\.\.[/\\]){2,}|(\.\.[/\\]).*(etc/passwd|win\.ini|boot\.ini)|/etc/(passwd|shadow)\b|\.\.%2f`)},
	{"jndi-injection", regexp.MustCompile(`(?i)\$\{\s*(jndi|\$\{[^}]*\})\s*:`)},
	{"template-injection", regexp.MustCompile(`(\{\{.*(\*|\.constructor|__class__|config).*\}\}|\$\{[^}]*(jndi|runtime|exec|T\()[^}]*\}|#\{[^}]*\}|<%[^>]*%>)`)},
}

// InjectionClass returns the injection class a parameter value matches, or "". It decodes up to twice so
// double-encoded payloads are still seen, and only looks at the first 2 KiB.
func InjectionClass(v string) string {
	if v == "" {
		return ""
	}
	if len(v) > 2048 {
		v = v[:2048]
	}
	for i := 0; i < 2; i++ {
		for _, s := range injectionSigs {
			if s.re.MatchString(v) {
				return s.class
			}
		}
		d, err := url.QueryUnescape(v)
		if err != nil || d == v {
			break
		}
		v = d
	}
	return ""
}

// paramInjection scans every parameter value of a request. The returned label is the first class found,
// in the order of the span's parameter names. Values are not returned.
func paramInjection(s Span) string {
	for _, n := range s.ParamNames {
		if c := InjectionClass(s.ParamValues[n]); c != "" {
			return sigPrefix + c
		}
	}
	return ""
}
