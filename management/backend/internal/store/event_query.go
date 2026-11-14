package store

// event_query.go — a small KQL-style query language for the Events search box.
//
//	severity>=high and (host:web* or host:db*) and not user:SYSTEM
//	proc:powershell cmd:"-enc" dst:203.0.113.7
//	type:(process or network) port:443 -chrome
//
// Grammar (precedence low -> high: or, and / implicit and, not):
//
//	expr    := and ( "or" and )*
//	and     := not ( ["and"] not )*          adjacent terms are ANDed
//	not     := ("not" | "-") not | primary
//	primary := "(" expr ")" | field op value | field ":" "(" v ("or" v)* ")" | term
//	op      := ":"  "="  "!="  ">"  ">="  "<"  "<="
//
// A word whose prefix is not a known field (10.0.0.1:443, C:\Windows\x) is a
// plain term, so existing searches keep working. Everything compiles to
// parameterised SQL; no user text is ever concatenated into a statement.

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	queryMaxLen   = 2000
	queryMaxNodes = 64
	queryMaxDepth = 12
)

// QueryError is a user-facing syntax problem (the API turns it into a 400).
type QueryError struct{ Msg string }

func (e *QueryError) Error() string { return e.Msg }

func qerr(f string, a ...interface{}) error { return &QueryError{fmt.Sprintf(f, a...)} }

type qkind int

const (
	qAnd qkind = iota
	qOr
	qNot
	qCond
	qTerm
)

// QueryExpr is a parsed query. The zero value / nil matches everything.
type QueryExpr struct {
	kind  qkind
	kids  []*QueryExpr
	field string
	op    string
	val   string
}

// ---- field table ------------------------------------------------------------

type fieldKind int

const (
	fText fieldKind = iota // substring / wildcard on text columns
	fIP                    // exact when a full IP, else substring
	fNum                   // numeric comparisons
	fSev
	fType
	fTime
)

type fieldSpec struct {
	kind fieldKind
	cols []string
}

var queryFields = map[string]fieldSpec{
	"host":     {fText, []string{"host"}},
	"os":       {fText, []string{"os"}},
	"user":     {fText, []string{"user_name"}},
	"proc":     {fText, []string{"process_name"}},
	"process":  {fText, []string{"process_name"}},
	"cmd":      {fText, []string{"command_line"}},
	"cmdline":  {fText, []string{"command_line"}},
	"image":    {fText, []string{"image_path"}},
	"file":     {fText, []string{"file_path"}},
	"path":     {fText, []string{"file_path"}},
	"hash":     {fText, []string{"file_hash"}},
	"reg":      {fText, []string{"reg_key"}},
	"regkey":   {fText, []string{"reg_key"}},
	"regvalue": {fText, []string{"reg_value"}},
	"domain":   {fText, []string{"domain"}},
	"channel":  {fText, []string{"channel"}},
	"source":   {fText, []string{"source"}},
	"proto":    {fText, []string{"proto"}},
	"guid":     {fText, []string{"process_guid"}},
	"logon":    {fText, []string{"logon_id"}},
	"src":      {fIP, []string{"src_ip"}},
	"src_ip":   {fIP, []string{"src_ip"}},
	"dst":      {fIP, []string{"dst_ip"}},
	"dst_ip":   {fIP, []string{"dst_ip"}},
	"ip":       {fIP, []string{"src_ip", "dst_ip"}},
	"pid":      {fNum, []string{"pid"}},
	"ppid":     {fNum, []string{"ppid"}},
	"port":     {fNum, []string{"dst_port", "src_port"}},
	"dstport":  {fNum, []string{"dst_port"}},
	"srcport":  {fNum, []string{"src_port"}},
	"event_id": {fNum, []string{"event_id"}},
	"eid":      {fNum, []string{"event_id"}},
	"sev":      {fSev, []string{"severity"}},
	"severity": {fSev, []string{"severity"}},
	"type":     {fType, []string{"event_type"}},
	"event":    {fType, []string{"event_type"}},
	"time":     {fTime, []string{"time"}},
}

// QueryFieldNames lists the supported field names (for help and tests).
func QueryFieldNames() []string {
	out := make([]string, 0, len(queryFields))
	for k := range queryFields {
		out = append(out, k)
	}
	return out
}

var severityNames = map[string]int{"info": 1, "low": 2, "medium": 3, "med": 3, "high": 4, "critical": 5, "crit": 5}

// LooksLikeQuery reports whether raw uses syntax beyond plain terms, so the UI
// can route it through the parser instead of treating it as one search word.
func LooksLikeQuery(raw string) bool {
	l := " " + strings.ToLower(raw) + " "
	if strings.ContainsAny(l, "()") || strings.Contains(l, " and ") || strings.Contains(l, " or ") || strings.Contains(l, " not ") {
		return true
	}
	for _, w := range strings.Fields(raw) {
		if f, _, _, ok := splitFieldOp(w); ok {
			if _, known := queryFields[f]; known {
				return true
			}
		}
	}
	return false
}

// ---- tokenizer --------------------------------------------------------------

type qtok struct {
	t   string // "(" ")" "word"
	s   string // raw text (quotes kept inside values)
	pos int
}

func tokenize(s string) ([]qtok, error) {
	var out []qtok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')':
			out = append(out, qtok{t: string(c), s: string(c), pos: i})
			i++
		default:
			start := i
			inQ := false
			for i < len(s) {
				ch := s[i]
				if ch == '"' {
					inQ = !inQ
					i++
					continue
				}
				if !inQ && (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ')') {
					break
				}
				if !inQ && ch == '(' { // field:( ... ) is field: followed by a group
					break
				}
				i++
			}
			if inQ {
				return nil, qerr("unterminated quote starting at position %d", start+1)
			}
			if i == start {
				i++ // stray character; skip
				continue
			}
			out = append(out, qtok{t: "word", s: s[start:i], pos: start})
		}
	}
	return out, nil
}

// splitFieldOp splits "field>=value" into its parts. ok is false when the
// word has no operator or the left side is not a plain identifier.
func splitFieldOp(w string) (field, op, val string, ok bool) {
	idx := strings.IndexAny(w, ":=<>!")
	if idx <= 0 {
		return
	}
	field = strings.ToLower(w[:idx])
	for _, r := range field {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return "", "", "", false
		}
	}
	rest := w[idx:]
	switch {
	case strings.HasPrefix(rest, ">="), strings.HasPrefix(rest, "<="), strings.HasPrefix(rest, "!="):
		op, val = rest[:2], rest[2:]
	case strings.HasPrefix(rest, ">"), strings.HasPrefix(rest, "<"), strings.HasPrefix(rest, "="), strings.HasPrefix(rest, ":"):
		op, val = rest[:1], rest[1:]
	default:
		return "", "", "", false
	}
	return field, op, val, true
}

// ---- parser -----------------------------------------------------------------

type qparser struct {
	toks  []qtok
	i     int
	nodes int
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`)
	}
	return strings.ReplaceAll(v, `"`, "")
}

// ParseEventQuery parses raw into an expression. An empty query yields nil.
func ParseEventQuery(raw string) (*QueryExpr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > queryMaxLen {
		return nil, qerr("query is too long (max %d characters)", queryMaxLen)
	}
	toks, err := tokenize(raw)
	if err != nil {
		return nil, err
	}
	p := &qparser{toks: toks}
	e, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.toks) {
		t := p.toks[p.i]
		if t.t == ")" {
			return nil, qerr("unmatched ')' at position %d", t.pos+1)
		}
		return nil, qerr("unexpected %q at position %d", t.s, t.pos+1)
	}
	return e, nil
}

func (p *qparser) peek() *qtok {
	if p.i < len(p.toks) {
		return &p.toks[p.i]
	}
	return nil
}

func isKW(t *qtok, kw string) bool { return t != nil && t.t == "word" && strings.EqualFold(t.s, kw) }

func (p *qparser) node(n *QueryExpr) (*QueryExpr, error) {
	p.nodes++
	if p.nodes > queryMaxNodes {
		return nil, qerr("query is too complex (max %d conditions)", queryMaxNodes)
	}
	return n, nil
}

func (p *qparser) parseOr(depth int) (*QueryExpr, error) {
	if depth > queryMaxDepth {
		return nil, qerr("query is nested too deeply")
	}
	first, err := p.parseAnd(depth)
	if err != nil {
		return nil, err
	}
	kids := []*QueryExpr{first}
	for isKW(p.peek(), "or") {
		p.i++
		if p.peek() == nil || p.peek().t == ")" {
			return nil, qerr("expected a condition after 'or'")
		}
		k, err := p.parseAnd(depth)
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	if len(kids) == 1 {
		return first, nil
	}
	return p.node(&QueryExpr{kind: qOr, kids: kids})
}

func (p *qparser) parseAnd(depth int) (*QueryExpr, error) {
	first, err := p.parseNot(depth)
	if err != nil {
		return nil, err
	}
	kids := []*QueryExpr{first}
	for {
		t := p.peek()
		if t == nil || t.t == ")" || isKW(t, "or") {
			break
		}
		if isKW(t, "and") {
			p.i++
			if p.peek() == nil || p.peek().t == ")" {
				return nil, qerr("expected a condition after 'and'")
			}
		}
		k, err := p.parseNot(depth)
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	if len(kids) == 1 {
		return first, nil
	}
	return p.node(&QueryExpr{kind: qAnd, kids: kids})
}

func (p *qparser) parseNot(depth int) (*QueryExpr, error) {
	t := p.peek()
	if t == nil {
		return nil, qerr("the query ends where a condition was expected")
	}
	if isKW(t, "not") {
		p.i++
		k, err := p.parseNot(depth + 1)
		if err != nil {
			return nil, err
		}
		return p.node(&QueryExpr{kind: qNot, kids: []*QueryExpr{k}})
	}
	if t.t == "word" && len(t.s) > 1 && t.s[0] == '-' && !strings.HasPrefix(t.s, "--") {
		// -term / -field:value
		p.toks[p.i].s = t.s[1:]
		k, err := p.parsePrimary(depth)
		if err != nil {
			return nil, err
		}
		return p.node(&QueryExpr{kind: qNot, kids: []*QueryExpr{k}})
	}
	return p.parsePrimary(depth)
}

func (p *qparser) parsePrimary(depth int) (*QueryExpr, error) {
	t := p.peek()
	if t == nil {
		return nil, qerr("the query ends where a condition was expected")
	}
	if t.t == "(" {
		p.i++
		if p.peek() != nil && p.peek().t == ")" {
			return nil, qerr("empty parentheses at position %d", t.pos+1)
		}
		e, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.peek() == nil || p.peek().t != ")" {
			return nil, qerr("missing ')' to close the '(' at position %d", t.pos+1)
		}
		p.i++
		return e, nil
	}
	if t.t == ")" {
		return nil, qerr("unexpected ')' at position %d", t.pos+1)
	}
	p.i++
	if f, op, val, ok := splitFieldOp(t.s); ok {
		if spec, known := queryFields[f]; known {
			_ = spec
			// field:(a or b)  -> OR of conditions on the same field
			if val == "" && p.peek() != nil && p.peek().t == "(" {
				return p.parseValueGroup(f, op, depth)
			}
			if val == "" {
				return nil, qerr("%s%s needs a value", f, op)
			}
			return p.node(&QueryExpr{kind: qCond, field: f, op: op, val: unquote(val)})
		}
	}
	w := unquote(t.s)
	if w == "" {
		return nil, qerr("empty term at position %d", t.pos+1)
	}
	return p.node(&QueryExpr{kind: qTerm, val: w})
}

func (p *qparser) parseValueGroup(field, op string, depth int) (*QueryExpr, error) {
	open := p.peek()
	p.i++ // "("
	var kids []*QueryExpr
	for {
		t := p.peek()
		if t == nil {
			return nil, qerr("missing ')' to close the '(' at position %d", open.pos+1)
		}
		if t.t == ")" {
			p.i++
			break
		}
		if t.t == "(" {
			return nil, qerr("nested parentheses are not supported inside %s:( )", field)
		}
		p.i++
		if isKW(t, "or") || t.s == "," {
			continue
		}
		for _, v := range strings.Split(t.s, ",") {
			if v = unquote(strings.TrimSpace(v)); v != "" {
				k, err := p.node(&QueryExpr{kind: qCond, field: field, op: op, val: v})
				if err != nil {
					return nil, err
				}
				kids = append(kids, k)
			}
		}
	}
	if len(kids) == 0 {
		return nil, qerr("%s:( ) has no values", field)
	}
	if len(kids) == 1 {
		return kids[0], nil
	}
	return p.node(&QueryExpr{kind: qOr, kids: kids})
}

// ---- compiler ---------------------------------------------------------------

type qsql struct {
	n    int
	args []interface{}
}

func (c *qsql) arg(v interface{}) string {
	c.args = append(c.args, v)
	s := fmt.Sprintf("$%d", c.n)
	c.n++
	return s
}

// SQL renders the expression as a WHERE fragment using placeholders starting
// at $start. A nil expression yields an empty fragment.
func (e *QueryExpr) SQL(start int) (string, []interface{}, error) {
	if e == nil {
		return "", nil, nil
	}
	c := &qsql{n: start}
	s, err := c.compile(e)
	if err != nil {
		return "", nil, err
	}
	return s, c.args, nil
}

func (c *qsql) compile(e *QueryExpr) (string, error) {
	switch e.kind {
	case qAnd, qOr:
		sep := " AND "
		if e.kind == qOr {
			sep = " OR "
		}
		parts := make([]string, 0, len(e.kids))
		for _, k := range e.kids {
			s, err := c.compile(k)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "(" + strings.Join(parts, sep) + ")", nil
	case qNot:
		s, err := c.compile(e.kids[0])
		if err != nil {
			return "", err
		}
		return "NOT (" + s + ")", nil
	case qTerm:
		return c.term(e.val), nil
	}
	return c.cond(e)
}

func likePattern(v string) (pat string, wild bool) {
	if !strings.Contains(v, "*") {
		return "%" + escapeLike(v) + "%", false
	}
	parts := strings.Split(v, "*")
	for i := range parts {
		parts[i] = escapeLike(parts[i])
	}
	return strings.Join(parts, "%"), true
}

func (c *qsql) term(v string) string {
	p := c.arg("%" + escapeLike(v) + "%")
	cols := []string{"host", "user_name", "process_name", "command_line", "src_ip", "dst_ip", "image_path", "file_path",
		"event_type", "source", "os", "reg_key", "reg_value", "file_hash", "domain"}
	parts := make([]string, 0, len(cols)+1)
	for _, col := range cols {
		parts = append(parts, fmt.Sprintf("COALESCE(%s::text,'') ILIKE %s", col, p))
	}
	parts = append(parts, "raw::text ILIKE "+p)
	return "(" + strings.Join(parts, " OR ") + ")"
}

func (c *qsql) cond(e *QueryExpr) (string, error) {
	spec := queryFields[e.field]
	switch spec.kind {
	case fText:
		return c.textCond(spec.cols, e)
	case fIP:
		return c.ipCond(spec.cols, e)
	case fNum:
		return c.numCond(spec.cols, e)
	case fSev:
		return c.sevCond(e)
	case fType:
		return c.typeCond(e)
	case fTime:
		return c.timeCond(e)
	}
	return "", qerr("unsupported field %q", e.field)
}

func anyOf(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

func (c *qsql) textCond(cols []string, e *QueryExpr) (string, error) {
	var parts []string
	switch e.op {
	case ":":
		pat, _ := likePattern(e.val)
		a := c.arg(pat)
		for _, col := range cols {
			parts = append(parts, fmt.Sprintf("COALESCE(%s::text,'') ILIKE %s", col, a))
		}
		return anyOf(parts), nil
	case "=", "!=":
		var s string
		if strings.Contains(e.val, "*") {
			pat, _ := likePattern(e.val)
			a := c.arg(pat)
			for _, col := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(%s::text,'') ILIKE %s", col, a))
			}
		} else {
			a := c.arg(strings.ToLower(e.val))
			for _, col := range cols {
				parts = append(parts, fmt.Sprintf("lower(COALESCE(%s::text,'')) = %s", col, a))
			}
		}
		s = anyOf(parts)
		if e.op == "!=" {
			s = "NOT " + s
		}
		return s, nil
	}
	return "", qerr("%s supports :, = and != (not %s)", e.field, e.op)
}

func (c *qsql) ipCond(cols []string, e *QueryExpr) (string, error) {
	var parts []string
	exact := net.ParseIP(e.val) != nil
	switch e.op {
	case ":", "=", "!=":
		var a string
		if exact {
			a = c.arg(e.val)
			for _, col := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(%s::text,'') = %s", col, a))
			}
		} else {
			pat, _ := likePattern(e.val)
			a = c.arg(pat)
			for _, col := range cols {
				parts = append(parts, fmt.Sprintf("COALESCE(%s::text,'') ILIKE %s", col, a))
			}
		}
		s := anyOf(parts)
		if e.op == "!=" {
			s = "NOT " + s
		}
		return s, nil
	}
	return "", qerr("%s supports :, = and != (not %s)", e.field, e.op)
}

func cmpSQL(op string) (string, bool) {
	switch op {
	case ":", "=":
		return "=", true
	case "!=":
		return "<>", true
	case ">", ">=", "<", "<=":
		return op, true
	}
	return "", false
}

func (c *qsql) numCond(cols []string, e *QueryExpr) (string, error) {
	n, err := strconv.ParseInt(e.val, 10, 64)
	if err != nil {
		return "", qerr("%s expects a number, got %q", e.field, e.val)
	}
	op, ok := cmpSQL(e.op)
	if !ok {
		return "", qerr("bad operator %q for %s", e.op, e.field)
	}
	a := c.arg(n)
	eq := "="
	if e.op != "!=" {
		eq = op
	}
	var parts []string
	for _, col := range cols {
		parts = append(parts, fmt.Sprintf("(%s IS NOT NULL AND %s %s %s)", col, col, eq, a))
	}
	if e.op == "!=" {
		// port!=443 means neither side is 443 (events with no port satisfy it)
		return "NOT " + anyOf(parts), nil
	}
	return anyOf(parts), nil
}

func (c *qsql) sevCond(e *QueryExpr) (string, error) {
	v := strings.ToLower(e.val)
	n, ok := severityNames[v]
	if !ok {
		num, err := strconv.Atoi(v)
		if err != nil || num < 1 || num > 5 {
			return "", qerr("severity must be info, low, medium, high, critical or 1-5 (got %q)", e.val)
		}
		n = num
	}
	op := ">="
	switch e.op {
	case ":":
		op = ">=" // "sev:high" means high or worse (matches the filter chips)
	case "=":
		op = "="
	case "!=":
		op = "<>"
	default:
		op = e.op
	}
	return fmt.Sprintf("severity %s %s", op, c.arg(n)), nil
}

func (c *qsql) typeCond(e *QueryExpr) (string, error) {
	v := strings.ToLower(e.val)
	if v == "cloud" {
		v = "cloud.*"
	}
	var s string
	if strings.Contains(v, "*") {
		pat, _ := likePattern(v)
		s = "event_type ILIKE " + c.arg(pat)
	} else {
		s = "lower(event_type) = " + c.arg(v)
	}
	switch e.op {
	case ":", "=":
		return s, nil
	case "!=":
		return "NOT (" + s + ")", nil
	}
	return "", qerr("type supports :, = and != (not %s)", e.op)
}

func parseQueryTime(v string) (time.Time, bool) {
	for _, l := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(l, v, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (c *qsql) timeCond(e *QueryExpr) (string, error) {
	t, ok := parseQueryTime(e.val)
	if !ok {
		return "", qerr("time expects a date like 2026-11-14 or 2026-11-14T10:30 (UTC), got %q", e.val)
	}
	op := ""
	switch e.op {
	case ">", ">=", "<", "<=":
		op = e.op
	case ":", "=":
		return "(time >= " + c.arg(t) + " AND time < " + c.arg(t.Add(24*time.Hour)) + ")", nil
	default:
		return "", qerr("time supports >, >=, <, <= and :")
	}
	return "time " + op + " " + c.arg(t), nil
}
