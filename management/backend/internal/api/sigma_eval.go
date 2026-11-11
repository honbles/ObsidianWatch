package api

// A real Sigma evaluator. The previous matcher ignored value modifiers
// (|all, |endswith, |re ...), fell back to searching the whole event text for
// any field it did not know, ignored the rule's logsource and had no boolean
// conditions — so rules fired on almost every process event. This one:
//
//   - parses the detection block as YAML;
//   - implements contains/startswith/endswith/all/re/cased/windash/cidr/exists
//     /numeric comparisons, wildcards, null, keyword lists and OR-of-maps;
//   - evaluates conditions with and/or/not/parentheses and "1 of"/"all of";
//   - gates each rule on its logsource (category/product/service);
//   - evaluates a rule only if every field it references is actually present
//     in our telemetry for that event (a missing field never "matches" and a
//     missing exclusion field can never silently turn a filter off).
//
// Anything it cannot evaluate faithfully (base64 modifiers, aggregations,
// fieldref ...) marks the rule unsupported and it never fires.

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"obsidianwatch/management/internal/store"
)

type sigmaMatcher struct {
	field  string
	all    bool
	exists *bool
	null   bool
	vals   []sigmaValue
}

type sigmaValue struct {
	re   *regexp.Regexp // string / wildcard / re modifiers
	cidr *net.IPNet
	num  *float64
	op   string // "", lt, lte, gt, gte
}

type sigmaSel struct {
	groups   [][]*sigmaMatcher // OR of AND-groups
	keywords []*regexp.Regexp  // keyword selection (OR)
}

type sigmaNode struct {
	kind string // sel | and | or | not | of
	name string
	subs []*sigmaNode
	all  bool   // of: "all of" vs "1 of"
	pat  string // of: selection glob or "them"
}

type sigmaCompiled struct {
	sels      map[string]*sigmaSel
	cond      *sigmaNode
	fields    []string
	supported bool
	why       string
	category  string
	product   string
	service   string
}

var sigmaCache sync.Map // rule.ID@UpdatedAt -> *sigmaCompiled

func getSigmaCompiled(rule store.SigmaRule) *sigmaCompiled {
	key := rule.ID + "@" + rule.UpdatedAt.String()
	if v, ok := sigmaCache.Load(key); ok {
		return v.(*sigmaCompiled)
	}
	c := compileSigma(rule)
	sigmaCache.Store(key, c)
	return c
}

func (c *sigmaCompiled) fail(format string, a ...interface{}) *sigmaCompiled {
	c.supported, c.why = false, fmt.Sprintf(format, a...)
	return c
}

// sigmaGlob converts a Sigma wildcard string (* and ?) to a regexp body.
func sigmaGlob(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch {
		case rs[i] == '\\' && i+1 < len(rs) && (rs[i+1] == '*' || rs[i+1] == '?'):
			b.WriteString(regexp.QuoteMeta(string(rs[i+1])))
			i++
		case rs[i] == '*':
			b.WriteString(".*")
		case rs[i] == '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(rs[i])))
		}
	}
	return b.String()
}

func scalarString(v interface{}) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case uint64:
		return strconv.FormatUint(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}

func compileSigma(rule store.SigmaRule) *sigmaCompiled {
	c := &sigmaCompiled{sels: map[string]*sigmaSel{}, supported: true}

	var ls map[string]map[string]interface{}
	if yaml.Unmarshal([]byte(rule.LogSource), &ls) == nil {
		for k, v := range ls["logsource"] {
			s, _ := scalarString(v)
			switch strings.ToLower(k) {
			case "category":
				c.category = strings.ToLower(s)
			case "product":
				c.product = strings.ToLower(s)
			case "service":
				c.service = strings.ToLower(s)
			}
		}
	}

	var doc map[string]map[string]interface{}
	if err := yaml.Unmarshal([]byte(rule.Detection), &doc); err != nil {
		return c.fail("detection yaml: %v", err)
	}
	det := doc["detection"]
	if len(det) == 0 {
		return c.fail("empty detection")
	}
	if _, ok := det["timeframe"]; ok {
		return c.fail("timeframe/aggregation not supported")
	}
	var conds []string
	switch cv := det["condition"].(type) {
	case string:
		conds = []string{cv}
	case []interface{}:
		for _, x := range cv {
			if s, ok := x.(string); ok {
				conds = append(conds, s)
			}
		}
	}
	if len(conds) == 0 {
		return c.fail("no condition")
	}
	fieldSet := map[string]bool{}
	for name, body := range det {
		if name == "condition" {
			continue
		}
		sel, err := compileSigmaSel(body, fieldSet)
		if err != nil {
			return c.fail("selection %s: %v", name, err)
		}
		c.sels[strings.ToLower(name)] = sel
	}
	var nodes []*sigmaNode
	for _, cs := range conds {
		n, err := parseSigmaCondition(cs, c.sels)
		if err != nil {
			return c.fail("condition %q: %v", cs, err)
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 1 {
		c.cond = nodes[0]
	} else {
		c.cond = &sigmaNode{kind: "or", subs: nodes}
	}
	for f := range fieldSet {
		c.fields = append(c.fields, f)
	}
	return c
}

func compileSigmaSel(body interface{}, fields map[string]bool) (*sigmaSel, error) {
	sel := &sigmaSel{}
	switch b := body.(type) {
	case map[string]interface{}:
		g, err := compileSigmaMap(b, fields)
		if err != nil {
			return nil, err
		}
		sel.groups = [][]*sigmaMatcher{g}
	case []interface{}:
		for _, it := range b {
			switch x := it.(type) {
			case map[string]interface{}:
				g, err := compileSigmaMap(x, fields)
				if err != nil {
					return nil, err
				}
				sel.groups = append(sel.groups, g)
			default:
				s, ok := scalarString(it)
				if !ok {
					return nil, fmt.Errorf("unsupported keyword value")
				}
				re, err := regexp.Compile(`(?is).*` + sigmaGlob(s) + `.*`)
				if err != nil {
					return nil, err
				}
				sel.keywords = append(sel.keywords, re)
			}
		}
	default:
		s, ok := scalarString(body)
		if !ok {
			return nil, fmt.Errorf("unsupported selection")
		}
		re, err := regexp.Compile(`(?is).*` + sigmaGlob(s) + `.*`)
		if err != nil {
			return nil, err
		}
		sel.keywords = append(sel.keywords, re)
	}
	return sel, nil
}

func compileSigmaMap(m map[string]interface{}, fields map[string]bool) ([]*sigmaMatcher, error) {
	var out []*sigmaMatcher
	for key, val := range m {
		parts := strings.Split(key, "|")
		mm := &sigmaMatcher{field: strings.ToLower(parts[0])}
		fields[mm.field] = true
		mods := map[string]bool{}
		for _, p := range parts[1:] {
			mods[strings.ToLower(p)] = true
		}
		for md := range mods {
			switch md {
			case "contains", "startswith", "endswith", "all", "re", "cased", "windash", "cidr", "exists", "lt", "lte", "gt", "gte", "i", "m", "s":
			default:
				return nil, fmt.Errorf("modifier %q not supported", md)
			}
		}
		mm.all = mods["all"]
		var vs []interface{}
		if l, ok := val.([]interface{}); ok {
			vs = l
		} else {
			vs = []interface{}{val}
		}
		if mods["exists"] {
			if len(vs) != 1 {
				return nil, fmt.Errorf("exists takes one bool")
			}
			b, ok := vs[0].(bool)
			if !ok {
				return nil, fmt.Errorf("exists takes a bool")
			}
			mm.exists = &b
			out = append(out, mm)
			continue
		}
		for _, v := range vs {
			if v == nil {
				mm.null = true
				continue
			}
			s, ok := scalarString(v)
			if !ok {
				return nil, fmt.Errorf("unsupported value type")
			}
			sv := sigmaValue{}
			switch {
			case mods["lt"] || mods["lte"] || mods["gt"] || mods["gte"]:
				f, err := strconv.ParseFloat(s, 64)
				if err != nil {
					return nil, err
				}
				sv.num = &f
				for _, o := range []string{"lte", "gte", "lt", "gt"} {
					if mods[o] {
						sv.op = o
						break
					}
				}
			case mods["cidr"]:
				_, n, err := net.ParseCIDR(s)
				if err != nil {
					return nil, err
				}
				sv.cidr = n
			case mods["re"]:
				flags := ""
				if !mods["cased"] {
					flags += "i"
				}
				if mods["m"] {
					flags += "m"
				}
				if mods["s"] {
					flags += "s"
				}
				pre := ""
				if flags != "" {
					pre = "(?" + flags + ")"
				}
				re, err := regexp.Compile(pre + s)
				if err != nil {
					return nil, err
				}
				sv.re = re
			default:
				variants := []string{s}
				if mods["windash"] {
					variants = append(variants, strings.ReplaceAll(s, "-", "/"))
				}
				var alts []string
				for _, vv := range variants {
					g := sigmaGlob(vv)
					switch {
					case mods["contains"]:
						g = ".*" + g + ".*"
					case mods["startswith"]:
						g = g + ".*"
					case mods["endswith"]:
						g = ".*" + g
					}
					alts = append(alts, g)
				}
				pre := "(?s"
				if !mods["cased"] {
					pre = "(?is"
				}
				re, err := regexp.Compile(pre + `)^(?:` + strings.Join(alts, "|") + `)$`)
				if err != nil {
					return nil, err
				}
				sv.re = re
			}
			mm.vals = append(mm.vals, sv)
		}
		out = append(out, mm)
	}
	return out, nil
}

// ── condition parser ────────────────────────────────────────────────────────

func sigmaTokens(cond string) ([]string, error) {
	if strings.Contains(cond, "|") {
		return nil, fmt.Errorf("aggregation not supported")
	}
	var out []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range cond {
		switch {
		case r == '(' || r == ')':
			flush()
			out = append(out, string(r))
		case r == ' ' || r == '\t' || r == '\n':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out, nil
}

func parseSigmaCondition(cond string, sels map[string]*sigmaSel) (*sigmaNode, error) {
	toks, err := sigmaTokens(cond)
	if err != nil {
		return nil, err
	}
	p := &sigmaParser{toks: toks, sels: sels}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.i != len(p.toks) {
		return nil, fmt.Errorf("unexpected %q", p.toks[p.i])
	}
	return n, nil
}

type sigmaParser struct {
	toks []string
	i    int
	sels map[string]*sigmaSel
}

func (p *sigmaParser) peek() string {
	if p.i < len(p.toks) {
		return strings.ToLower(p.toks[p.i])
	}
	return ""
}

func (p *sigmaParser) or() (*sigmaNode, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	subs := []*sigmaNode{l}
	for p.peek() == "or" {
		p.i++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		subs = append(subs, r)
	}
	if len(subs) == 1 {
		return l, nil
	}
	return &sigmaNode{kind: "or", subs: subs}, nil
}

func (p *sigmaParser) and() (*sigmaNode, error) {
	l, err := p.not()
	if err != nil {
		return nil, err
	}
	subs := []*sigmaNode{l}
	for p.peek() == "and" {
		p.i++
		r, err := p.not()
		if err != nil {
			return nil, err
		}
		subs = append(subs, r)
	}
	if len(subs) == 1 {
		return l, nil
	}
	return &sigmaNode{kind: "and", subs: subs}, nil
}

func (p *sigmaParser) not() (*sigmaNode, error) {
	if p.peek() == "not" {
		p.i++
		n, err := p.not()
		if err != nil {
			return nil, err
		}
		return &sigmaNode{kind: "not", subs: []*sigmaNode{n}}, nil
	}
	return p.atom()
}

func (p *sigmaParser) atom() (*sigmaNode, error) {
	t := p.peek()
	switch {
	case t == "":
		return nil, fmt.Errorf("unexpected end")
	case t == "(":
		p.i++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing )")
		}
		p.i++
		return n, nil
	case t == "1" || t == "all":
		p.i++
		if p.peek() != "of" {
			return nil, fmt.Errorf("expected 'of'")
		}
		p.i++
		pat := p.peek()
		if pat == "" || pat == "(" || pat == ")" {
			return nil, fmt.Errorf("expected selection pattern")
		}
		p.i++
		return &sigmaNode{kind: "of", all: t == "all", pat: pat}, nil
	}
	if _, ok := p.sels[t]; !ok {
		return nil, fmt.Errorf("unknown selection %q", t)
	}
	p.i++
	return &sigmaNode{kind: "sel", name: t}, nil
}

// ── evaluation ──────────────────────────────────────────────────────────────

type sigmaEvalCtx struct {
	ev    store.Event
	data  map[string]string // lowercased raw event_data / top-level scalars
	text  string
	cache map[string]bool
	sels  map[string]*sigmaSel
}

func (n *sigmaNode) eval(x *sigmaEvalCtx) bool {
	switch n.kind {
	case "sel":
		return x.sel(n.name)
	case "not":
		return !n.subs[0].eval(x)
	case "and":
		for _, s := range n.subs {
			if !s.eval(x) {
				return false
			}
		}
		return true
	case "or":
		for _, s := range n.subs {
			if s.eval(x) {
				return true
			}
		}
		return false
	case "of":
		matched, total := 0, 0
		for name := range x.sels {
			if n.pat != "them" {
				g, err := regexp.Compile(`(?i)^` + sigmaGlob(n.pat) + `$`)
				if err != nil || !g.MatchString(name) {
					continue
				}
			}
			total++
			if x.sel(name) {
				matched++
			}
		}
		if total == 0 {
			return false
		}
		if n.all {
			return matched == total
		}
		return matched > 0
	}
	return false
}

func (x *sigmaEvalCtx) sel(name string) bool {
	if v, ok := x.cache[name]; ok {
		return v
	}
	s := x.sels[name]
	res := false
	if s != nil {
		for _, kw := range s.keywords {
			if kw.MatchString(x.text) {
				res = true
				break
			}
		}
		if !res {
			for _, g := range s.groups {
				ok := true
				for _, m := range g {
					if !m.match(x) {
						ok = false
						break
					}
				}
				if ok && len(g) > 0 {
					res = true
					break
				}
			}
		}
	}
	x.cache[name] = res
	return res
}

func (m *sigmaMatcher) match(x *sigmaEvalCtx) bool {
	val, present := sigmaField(x, m.field)
	if m.exists != nil {
		return (present && val != "") == *m.exists
	}
	if val == "" {
		return m.null // "field: null" matches an empty/absent field
	}
	if len(m.vals) == 0 {
		return false
	}
	hit := func(v sigmaValue) bool {
		switch {
		case v.num != nil:
			f, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return false
			}
			switch v.op {
			case "lt":
				return f < *v.num
			case "lte":
				return f <= *v.num
			case "gt":
				return f > *v.num
			case "gte":
				return f >= *v.num
			}
			return false
		case v.cidr != nil:
			ip := net.ParseIP(strings.TrimSpace(val))
			return ip != nil && v.cidr.Contains(ip)
		case v.re != nil:
			return v.re.MatchString(val)
		}
		return false
	}
	if m.all {
		for _, v := range m.vals {
			if !hit(v) {
				return false
			}
		}
		return true
	}
	for _, v := range m.vals {
		if hit(v) {
			return true
		}
	}
	return false
}

func sigStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// sigmaRawData flattens the agent's event_data (Sysmon/EventLog fields) and
// top-level scalar raw keys into one lowercased map.
func sigmaRawData(ev store.Event) map[string]string {
	out := map[string]string{}
	if len(ev.Raw) == 0 {
		return out
	}
	var m map[string]interface{}
	if json.Unmarshal(ev.Raw, &m) != nil {
		return out
	}
	add := func(k string, v interface{}) {
		if s, ok := scalarString(v); ok {
			if _, exists := out[strings.ToLower(k)]; !exists {
				out[strings.ToLower(k)] = s
			}
		}
	}
	if ed, ok := m["event_data"].(map[string]interface{}); ok {
		for k, v := range ed {
			add(k, v)
		}
	}
	for k, v := range m {
		add(k, v)
	}
	return out
}

// sigmaField resolves a Sigma field name against an event. present=false means
// the field is not part of our telemetry for this event.
func sigmaField(x *sigmaEvalCtx, f string) (string, bool) {
	ev := x.ev
	pick := func(vals ...string) (string, bool) {
		for _, v := range vals {
			if v != "" {
				return v, true
			}
		}
		return "", true
	}
	switch f {
	case "image":
		if d, ok := x.data["image"]; ok && ev.EventType != "process" {
			return d, true
		}
		return pick(sigStr(ev.ImagePath), sigStr(ev.ProcessName))
	case "commandline":
		return pick(sigStr(ev.CommandLine))
	case "user", "username", "targetusername", "accountname":
		return pick(sigStr(ev.UserName))
	case "targetfilename", "filename":
		return pick(sigStr(ev.FilePath), x.data["targetfilename"])
	case "targetobject":
		if d, ok := x.data["targetobject"]; ok {
			return d, true
		}
		if ev.RegKey != nil {
			if ev.RegValue != nil && *ev.RegValue != "" {
				return *ev.RegKey + `\` + *ev.RegValue, true
			}
			return *ev.RegKey, true
		}
		return "", true
	case "details":
		if d, ok := x.data["details"]; ok {
			return d, true
		}
		return pick(sigStr(ev.RegData))
	case "destinationip":
		return pick(sigStr(ev.DstIP))
	case "sourceip":
		return pick(sigStr(ev.SrcIP))
	case "destinationport":
		if ev.DstPort != nil {
			return strconv.Itoa(*ev.DstPort), true
		}
		return "", true
	case "sourceport":
		if ev.SrcPort != nil {
			return strconv.Itoa(*ev.SrcPort), true
		}
		return "", true
	case "eventid":
		if ev.EventID != nil {
			return strconv.FormatUint(uint64(*ev.EventID), 10), true
		}
		return "", true
	case "channel":
		return pick(sigStr(ev.Channel))
	case "processid":
		if ev.PID != nil {
			return strconv.Itoa(*ev.PID), true
		}
		return "", true
	case "parentprocessid":
		if ev.PPID != nil {
			return strconv.Itoa(*ev.PPID), true
		}
		return "", true
	case "hashes", "hash", "md5", "sha1", "sha256", "imphash":
		if d, ok := x.data[f]; ok {
			return d, true
		}
		return pick(sigStr(ev.FileHash))
	case "computername", "computer":
		return pick(ev.Host)
	}
	d, ok := x.data[f]
	return d, ok
}

// ── gating ──────────────────────────────────────────────────────────────────

var sigmaSysmonCat = map[string][]uint32{
	"process_creation": {1}, "network_connection": {3}, "driver_load": {6}, "image_load": {7},
	"create_remote_thread": {8}, "process_access": {10}, "file_event": {11},
	"registry_add": {12}, "registry_delete": {12}, "registry_set": {13}, "registry_rename": {14}, "registry_event": {12, 13, 14},
	"pipe_created": {17, 18}, "dns_query": {22}, "file_delete": {23, 26}, "process_tampering": {25},
}

var sigmaEventTypeCat = map[string]string{
	"process_creation": "process", "file_event": "file", "file_change": "file", "file_delete": "file", "file_rename": "file",
	"registry_add": "registry", "registry_delete": "registry", "registry_set": "registry", "registry_event": "registry",
	"network_connection": "network", "dns_query": "dns",
}

var sigmaServiceChannel = map[string]string{
	"security": "security", "system": "system", "application": "application",
	"powershell": "powershell", "powershell-classic": "powershell", "sysmon": "sysmon",
	"taskscheduler": "taskscheduler", "wmi": "wmi-activity", "windefend": "windows defender",
	"bits-client": "bits-client", "dns-server": "dns-server", "driver-framework": "driverframeworks",
	"firewall-as": "windows firewall", "ntlm": "ntlm", "openssh": "openssh", "terminalservices-localsessionmanager": "terminalservices",
}

func sigmaApplies(c *sigmaCompiled, ev store.Event) bool {
	os := strings.ToLower(ev.OS)
	switch c.product {
	case "windows":
		if os != "windows" {
			return false
		}
	case "linux":
		if os != "linux" {
			return false
		}
	case "macos":
		if os != "macos" && os != "darwin" {
			return false
		}
	case "":
	default:
		return false
	}
	if c.category != "" {
		if want, ok := sigmaEventTypeCat[c.category]; ok && ev.EventType == want {
			return true
		}
		if ids, ok := sigmaSysmonCat[c.category]; ok && ev.EventType == "sysmon" && ev.EventID != nil {
			for _, id := range ids {
				if *ev.EventID == id {
					return true
				}
			}
		}
		return false
	}
	if c.service != "" {
		tok, ok := sigmaServiceChannel[c.service]
		return ok && ev.Channel != nil && strings.Contains(strings.ToLower(*ev.Channel), tok)
	}
	return false
}

// matchSigmaRule reports whether a Sigma rule matches an event.
func matchSigmaRule(rule store.SigmaRule, ev store.Event) bool {
	c := getSigmaCompiled(rule)
	if !c.supported || c.cond == nil || !sigmaApplies(c, ev) {
		return false
	}
	x := &sigmaEvalCtx{ev: ev, data: sigmaRawData(ev), cache: map[string]bool{}, sels: c.sels}
	// Every referenced field must exist in our telemetry for this event.
	for _, f := range c.fields {
		if _, ok := sigmaField(x, f); !ok {
			return false
		}
	}
	x.text = strings.ToLower(sigStr(ev.CommandLine) + " " + sigStr(ev.ImagePath) + " " + sigStr(ev.ProcessName) + " " + sigStr(ev.FilePath) + " " + sigStr(ev.RegKey) + " " + sigStr(ev.RegData))
	return c.cond.eval(x)
}

// sigmaAlertSeverity damps noisy rule maturity: experimental rules alert Low,
// "test" rules Medium, stable rules keep their level. Deprecated/unsupported
// rules and informational ones never alert.
func sigmaAlertSeverity(rule store.SigmaRule) (int, bool) {
	switch strings.ToLower(rule.Status) {
	case "deprecated", "unsupported":
		return 0, false
	}
	if strings.EqualFold(rule.Level, "informational") {
		return 0, false
	}
	sev := rule.Severity
	switch strings.ToLower(rule.Status) {
	case "experimental":
		if sev > 2 {
			sev = 2
		}
	case "test":
		if sev > 3 {
			sev = 3
		}
	}
	return sev, sev > 0
}
