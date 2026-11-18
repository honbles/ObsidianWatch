package ebpf

import (
	"regexp"
	"strings"
)

// There is no argument redaction elsewhere in the Linux agent, so the sensor does its own before a
// command line leaves the process. It is deliberately conservative: it removes values that look like
// credentials and leaves everything else as it was.

var sensitiveWords = []string{"password", "passwd", "passphrase", "pwd", "secret", "token", "apikey", "api-key", "api_key",
	"auth", "credential", "private", "bearer", "cookie", "session", "signature", "access_key", "accesskey"}

var urlCreds = regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*://[^\s/:@]+):([^\s/@]+)@`)

const redacted = "[REDACTED]"

const maxCmdLen = 2048

func sensitiveKey(k string) bool {
	k = strings.ToLower(strings.TrimLeft(k, "-/"))
	for _, w := range sensitiveWords {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

// RedactCmd removes credential-looking values from a command line:
//
//	--password=hunter2        -> --password=[REDACTED]
//	--token abc123            -> --token [REDACTED]
//	API_KEY=abc curl ...      -> API_KEY=[REDACTED] curl ...
//	https://user:pw@host/x    -> https://user:[REDACTED]@host/x
//	-H "Authorization: Bearer abc" -> ... Bearer [REDACTED]
func RedactCmd(cmd string) string {
	if len(cmd) > maxCmdLen {
		cmd = cmd[:maxCmdLen]
	}
	cmd = urlCreds.ReplaceAllString(cmd, "${1}:"+redacted+"@")
	toks := strings.Split(cmd, " ")
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		low := strings.ToLower(t)
		switch {
		case low == "bearer" || low == "basic":
			if i+1 < len(toks) {
				toks[i+1] = redacted
				i++
			}
		case strings.Contains(t, "="):
			k, _, _ := strings.Cut(t, "=")
			if sensitiveKey(k) {
				toks[i] = k + "=" + redacted
			}
		case strings.HasPrefix(t, "-") && sensitiveKey(t):
			if i+1 < len(toks) && !strings.HasPrefix(toks[i+1], "-") {
				toks[i+1] = redacted
				i++
			}
		}
	}
	return strings.Join(toks, " ")
}
