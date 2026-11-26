package store

import "regexp"

// Saved searches used to be stored as the Events page's chip labels ("OS: windows Type: process
// Severity: 4 IP: 10.0.0.5"), which are not a query. NormalizeSavedQuery turns that form into the query
// language; a query that is already in it comes back unchanged. Migration 082 applies the same rewrite to
// stored rows; this keeps older exports and API clients working.
var legacyChip = []struct {
	re  *regexp.Regexp
	out string
}{
	{regexp.MustCompile(`(?i)(^|\s)OS: (\S+)`), "${1}os:${2}"},
	{regexp.MustCompile(`(?i)(^|\s)Type: (\S+)`), "${1}type:${2}"},
	{regexp.MustCompile(`(?i)(^|\s)Severity: ([1-5])`), "${1}sev>=${2}"},
	{regexp.MustCompile(`(?i)(^|\s)IP: (\S+)`), "${1}ip:${2}"},
	{regexp.MustCompile(`(?i)(^|\s)Port: (\d+)`), "${1}port:${2}"},
	{regexp.MustCompile(`(?i)(^|\s)Proto: (\S+)`), "${1}proto:${2}"},
	{regexp.MustCompile(`(?i)(^|\s)Source: (\S+)`), "${1}source:${2}"},
	{regexp.MustCompile(`(?i)(^|\s)Host: (\S+)`), "${1}host:${2}"},
}

func NormalizeSavedQuery(q string) string {
	for _, c := range legacyChip {
		q = c.re.ReplaceAllString(q, c.out)
	}
	return q
}
