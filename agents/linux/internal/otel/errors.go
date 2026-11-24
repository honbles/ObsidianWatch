package otel

// errors.go - error tracking (APM spec item 4). A span's "exception" event carries a type, a message and a stack.
// The agent groups failures by a fingerprint (type, the top in-app frames, route) and forwards, per group and per
// flush, a count plus ONE scrubbed sample. Messages are dropped unless the service allows "masked" messages, and
// even then digits, quoted strings, emails, uuids and long opaque strings are replaced. Stack frames keep a
// function and a short file path with its line; column numbers and argument values are dropped. Caps: 30 frames,
// 4 KB of frames, 100 distinct groups per service per flush.

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxErrGroupsPerSvc = 100
	maxErrFrames       = 30
	maxErrFrameBytes   = 4096
	maxErrMessage      = 200
	fingerprintFrames  = 5
)

type errFrame struct {
	fn, file string
	line     int
	lib      bool
}

var (
	rePyFrame   = regexp.MustCompile(`^\s*File "(.+?)", line (\d+), in (.+?)\s*$`)
	reNetFrame  = regexp.MustCompile(`^\s*at ([^(]+)\(.*?\)(?: in (.+?):line (\d+))?\s*$`)
	reJavaFrame = regexp.MustCompile(`^\s*at ([\w$.<>/]+)\(((?:[\w$.-]+\.(?:java|kt|scala|groovy))|Native Method|Unknown Source)(?::(\d+))?\)\s*$`)
	reNodeFrame = regexp.MustCompile(`^\s*at (?:(.+?) \()?(.+?):(\d+)(?::\d+)?\)?\s*$`)

	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reQuoted = regexp.MustCompile(`"[^"]*"|'[^']*'|` + "`[^`]*`")
	reOpaque = regexp.MustCompile(`[A-Za-z0-9_\-+/=.]{20,}`)
)

func parseStack(stack string) []errFrame {
	var out []errFrame
	for _, ln := range strings.Split(stack, "\n") {
		if len(out) >= 200 {
			break
		}
		var f errFrame
		switch {
		case rePyFrame.MatchString(ln):
			m := rePyFrame.FindStringSubmatch(ln)
			f.file, f.fn = m[1], m[3]
			f.line, _ = strconv.Atoi(m[2])
		case reJavaFrame.MatchString(ln):
			m := reJavaFrame.FindStringSubmatch(ln)
			f.fn, f.file = m[1], m[2]
			f.line, _ = strconv.Atoi(m[3])
		case strings.Contains(ln, ":line ") && reNetFrame.MatchString(ln): // .NET with file info
			m := reNetFrame.FindStringSubmatch(ln)
			f.fn, f.file = strings.TrimSpace(m[1]), m[2]
			f.line, _ = strconv.Atoi(m[3])
		case reNodeFrame.MatchString(ln):
			m := reNodeFrame.FindStringSubmatch(ln)
			f.fn, f.file = m[1], m[2]
			f.line, _ = strconv.Atoi(m[3])
		default:
			continue
		}
		f.lib = isLibFrame(f)
		f.file = shortPath(f.file)
		f.fn = clipN(strings.TrimSpace(f.fn), 80)
		out = append(out, f)
	}
	return out
}

func isLibFrame(f errFrame) bool {
	p := strings.ReplaceAll(f.file, "\\", "/")
	for _, s := range []string{"node_modules/", "site-packages/", "dist-packages/", "/lib/python", "node:", "internal/"} {
		if strings.Contains(p, s) {
			return true
		}
	}
	for _, s := range []string{"java.", "javax.", "jdk.", "sun.", "kotlin.", "System.", "Microsoft."} {
		if strings.HasPrefix(f.fn, s) {
			return true
		}
	}
	return false
}

// shortPath keeps the last three path segments so the same file groups the same whether it runs from a
// container path or a developer machine.
func shortPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	parts := strings.Split(p, "/")
	if len(parts) > 3 {
		parts = parts[len(parts)-3:]
	}
	return clipN(strings.Join(parts, "/"), 120)
}

func (f errFrame) String() string {
	s := f.fn
	if s == "" {
		s = "<anonymous>"
	}
	if f.file != "" {
		s += " " + f.file
		if f.line > 0 {
			s += ":" + strconv.Itoa(f.line)
		}
	}
	return s
}

// errorFingerprint hashes the type, the top in-app frames (function and file, never the line, so a deploy that
// shifts lines keeps the group) and the route. With no in-app frame the top frames of any kind are used; with
// no stack at all, type and route alone.
func errorFingerprint(typ string, frames []errFrame, route string) string {
	var use []errFrame
	for _, f := range frames {
		if !f.lib {
			if use = append(use, f); len(use) == fingerprintFrames {
				break
			}
		}
	}
	if len(use) == 0 && len(frames) > 0 {
		n := 3
		if len(frames) < n {
			n = len(frames)
		}
		use = frames[:n]
	}
	var b strings.Builder
	b.WriteString(typ + "\x00" + route)
	for _, f := range use {
		b.WriteString("\x00" + f.fn + "@" + f.file)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// scrubMessage replaces anything in an error message that could be a value.
func scrubMessage(m string) string {
	m = strings.Join(strings.Fields(m), " ")
	m = reEmail.ReplaceAllString(m, "?")
	m = reUUID.ReplaceAllString(m, "?")
	m = reQuoted.ReplaceAllString(m, "?")
	m = reOpaque.ReplaceAllString(m, "?")
	m = reDigits.ReplaceAllString(m, "?")
	return clipN(m, maxErrMessage)
}

type errKey struct {
	svc svcKey
	fp  string
}

type errVal struct {
	route, method, typ, frame, msg, version, trace string
	frames                                         []string
	count                                          int64
	at                                             time.Time
}

// BatchError is one error group's occurrences since the last flush, with one scrubbed sample.
type BatchError struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Route       string    `json:"route,omitempty"`
	Method      string    `json:"method,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Type        string    `json:"type"`
	Frame       string    `json:"frame,omitempty"` // top in-app frame, function file:line
	Frames      []string  `json:"frames,omitempty"`
	Message     string    `json:"message,omitempty"` // only when the service allows masked messages
	Version     string    `json:"version,omitempty"`
	TraceID     string    `json:"trace_id,omitempty"`
	Count       int64     `json:"count"`
	Time        time.Time `json:"time"`
}

// noteError records one span's exception. route is the owning HTTP route, or "".
func (a *Aggregator) noteError(s *Span, route, method string, now time.Time) {
	d := a.diag()
	sv := svcKey{s.Res.Service, envOf(s.Res.Environment)}
	frames := parseStack(s.ExcStack)
	typ := clipN(s.ExcType, 128)
	fp := errorFingerprint(typ, frames, route)
	k := errKey{sv, fp}
	v := d.er[k]
	if v == nil {
		if d.erN[sv] >= maxErrGroupsPerSvc {
			a.Stats.ErrorDrops++
			return
		}
		d.erN[sv]++
		v = &errVal{route: route, method: method, typ: typ, version: clipN(s.Res.Version, 64), trace: s.TraceID, at: now}
		var out []string
		size := 0
		for _, f := range frames {
			ln := f.String()
			if len(out) >= maxErrFrames || size+len(ln) > maxErrFrameBytes {
				break
			}
			out = append(out, ln)
			size += len(ln)
		}
		v.frames = out
		for _, f := range frames {
			if !f.lib {
				v.frame = f.String()
				break
			}
		}
		if v.frame == "" && len(out) > 0 {
			v.frame = out[0]
		}
		if a.opt.ErrMsgFn != nil && a.opt.ErrMsgFn(sv.name, sv.env) == "masked" {
			v.msg = scrubMessage(s.ExcMsg)
		}
		d.er[k] = v
	}
	v.count++
}
