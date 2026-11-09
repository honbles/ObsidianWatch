package parser

import (
	"bufio"
	"io"
	"strings"
)

// MaxSyslogLine bounds one syslog message read from a TCP stream.
const MaxSyslogLine = 64 * 1024

// ScanSyslogLines calls fn for each non-empty newline-delimited message in r.
// Unlike splitting each Read() chunk, it reassembles messages that arrive
// across several TCP segments, so a line is never cut in half and parsed as
// two bogus messages. A line longer than MaxSyslogLine ends the stream with
// bufio.ErrTooLong instead of growing memory without limit.
func ScanSyslogLines(r io.Reader, fn func(line string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), MaxSyslogLine)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			fn(line)
		}
	}
	return sc.Err()
}
