package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// D-07 (first slice): a windowed correlation layer over authentication events
// from every source (Windows 4624/4625, Linux sshd/sudo, Entra sign-ins).
// Detects, per scope (host, or tenant for cloud):
//   - password spray: one source IP failing against many accounts
//   - brute force: many failures against one account
//   - success after failures: a successful logon right after a failure burst
// State is in memory (bounded and time-pruned); a restart forgets at most the
// last few minutes, and dedup keys keep a repeated condition from re-alerting.

const (
	authSprayWindow   = 10 * time.Minute
	authSprayUsers    = 10
	authBruteWindow   = 5 * time.Minute
	authBruteFails    = 10
	authSuccessWindow = 10 * time.Minute
	authSuccessFails  = 5
	authMaxKeys       = 20000
	authMFAWindow     = 10 * time.Minute
	authMFAFails      = 5
)

type authKind int

const (
	authNone authKind = iota
	authFail
	authSuccess
	authMFAFail
)

type authObs struct {
	kind  authKind
	scope string // host for endpoints, connector for cloud
	user  string
	ip    string
}

var logonTypeNetRe = regexp.MustCompile(`"logon_?type"\s*:\s*"?(3|10)"?[,}]`)

var sshFromRe = regexp.MustCompile(`\bfrom\s+([0-9a-fA-F:.]+)`)

// entra error codes that mean "credentials rejected" (not MFA prompts etc.).
var entraBadCredCodes = map[int]bool{50126: true, 50053: true, 50034: true, 50057: true, 50055: true, 50056: true}

func classifyAuth(ev store.Event) authObs {
	user := ""
	if ev.UserName != nil {
		user = strings.ToLower(normUser(*ev.UserName))
	}
	ip := ""
	if ev.SrcIP != nil {
		ip = *ev.SrcIP
	}
	switch {
	case ev.EventType == "cloud.entra_signin":
		var m struct {
			Status struct {
				ErrorCode int `json:"errorCode"`
			} `json:"status"`
		}
		if json.Unmarshal(ev.Raw, &m) != nil {
			return authObs{}
		}
		o := authObs{scope: ev.AgentID, user: user, ip: ip}
		if m.Status.ErrorCode == 0 {
			o.kind = authSuccess
		} else if m.Status.ErrorCode == 500121 {
			o.kind = authMFAFail // MFA challenge failed / denied / not answered
		} else if entraBadCredCodes[m.Status.ErrorCode] {
			o.kind = authFail
		}
		return o
	case ev.EventType == "logon" && ev.EventID != nil && (*ev.EventID == 4625 || *ev.EventID == 4624):
		o := authObs{scope: ev.Host, user: user, ip: ip}
		if *ev.EventID == 4625 {
			o.kind = authFail
		} else if lt := rawStr(ev); logonTypeNetRe.MatchString(lt) {
			o.kind = authSuccess // only network/RDP successes matter for success-after-failure
		}
		return o
	case ev.EventType == "logon" && ev.OS == "linux":
		var m struct {
			Action string `json:"action"`
		}
		if json.Unmarshal(ev.Raw, &m) != nil {
			return authObs{}
		}
		o := authObs{scope: ev.Host, user: user, ip: ip}
		if o.ip == "" && ev.CommandLine != nil {
			if sm := sshFromRe.FindStringSubmatch(*ev.CommandLine); sm != nil {
				o.ip = sm[1]
			}
		}
		switch m.Action {
		case "ssh_login_failure", "ssh_invalid_user":
			o.kind = authFail
		case "ssh_login_success":
			o.kind = authSuccess
		}
		return o
	}
	return authObs{}
}

type authHit struct {
	Rule, Title, Desc string
	Severity          int
	MITRE, Entity     string
	Bucket            int64
}

type authFailRec struct {
	t    time.Time
	user string
}

type authCorrelator struct {
	mu      sync.Mutex
	byIP    map[string][]authFailRec // scope|ip -> failures
	byUser  map[string][]time.Time   // scope|user -> failures
	ipFails map[string][]time.Time   // scope|user|ip -> failures (for success-after-failure)
	mfa     map[string][]time.Time   // scope|user -> failed MFA challenges
}

func newAuthCorrelator() *authCorrelator {
	return &authCorrelator{byIP: map[string][]authFailRec{}, byUser: map[string][]time.Time{}, ipFails: map[string][]time.Time{}, mfa: map[string][]time.Time{}}
}

func pruneTimes(ts []time.Time, cut time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	return ts[i:]
}

func (c *authCorrelator) Observe(ev store.Event) []authHit {
	o := classifyAuth(ev)
	if o.kind == authNone || o.user == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.byIP)+len(c.byUser)+len(c.ipFails)+len(c.mfa) > authMaxKeys*3 {
		c.mfa = map[string][]time.Time{}
		c.byIP, c.byUser, c.ipFails = map[string][]authFailRec{}, map[string][]time.Time{}, map[string][]time.Time{}
	}
	t := ev.Time
	var hits []authHit
	if o.kind == authMFAFail {
		// MFA fatigue / push bombing: repeated failed or unanswered MFA challenges
		// for one account means the password is known and someone is spamming prompts.
		uk := o.scope + "|" + o.user
		c.mfa[uk] = append(pruneTimes(c.mfa[uk], t.Add(-authMFAWindow)), t)
		if n := len(c.mfa[uk]); n >= authMFAFails {
			hits = append(hits, authHit{
				Rule: "CORR-AUTH-004", Title: fmt.Sprintf("Possible MFA fatigue attack on %s", o.user),
				Desc: fmt.Sprintf("%d failed or unanswered MFA challenges for %q within %s (latest source %s). The password may be compromised and the attacker is spamming approval prompts.",
					n, o.user, authMFAWindow, o.ip),
				Severity: 4, MITRE: "T1621", Entity: "mfa|" + uk, Bucket: t.Unix() / int64(authMFAWindow.Seconds()),
			})
		}
		return hits
	}
	if o.kind == authFail {
		if o.ip != "" {
			k := o.scope + "|" + o.ip
			recs := c.byIP[k]
			cut := t.Add(-authSprayWindow)
			j := 0
			for j < len(recs) && recs[j].t.Before(cut) {
				j++
			}
			recs = append(recs[j:], authFailRec{t, o.user})
			c.byIP[k] = recs
			users := map[string]bool{}
			for _, r := range recs {
				users[r.user] = true
			}
			if len(users) >= authSprayUsers {
				hits = append(hits, authHit{
					Rule: "CORR-AUTH-001", Title: fmt.Sprintf("Password spray from %s", o.ip),
					Desc: fmt.Sprintf("%s failed authentication against %d different accounts within %s on %s.",
						o.ip, len(users), authSprayWindow, ev.Host),
					Severity: 4, MITRE: "T1110.003", Entity: "spray|" + k, Bucket: t.Unix() / int64(authSprayWindow.Seconds()),
				})
			}
			fk := k + "|" + o.user
			c.ipFails[fk] = append(pruneTimes(c.ipFails[fk], t.Add(-authSuccessWindow)), t)
		}
		uk := o.scope + "|" + o.user
		c.byUser[uk] = append(pruneTimes(c.byUser[uk], t.Add(-authBruteWindow)), t)
		if n := len(c.byUser[uk]); n >= authBruteFails {
			hits = append(hits, authHit{
				Rule: "CORR-AUTH-002", Title: fmt.Sprintf("Brute force against account %s", o.user),
				Desc: fmt.Sprintf("%d failed authentications for %q within %s on %s (latest source %s).",
					n, o.user, authBruteWindow, ev.Host, o.ip),
				Severity: 3, MITRE: "T1110.001", Entity: "brute|" + uk, Bucket: t.Unix() / int64(authBruteWindow.Seconds()),
			})
		}
		return hits
	}
	// success
	if o.ip != "" {
		fk := o.scope + "|" + o.ip + "|" + o.user
		fails := pruneTimes(c.ipFails[fk], t.Add(-authSuccessWindow))
		c.ipFails[fk] = fails
		if len(fails) >= authSuccessFails {
			hits = append(hits, authHit{
				Rule: "CORR-AUTH-003", Title: fmt.Sprintf("Successful logon after %d failures: %s", len(fails), o.user),
				Desc: fmt.Sprintf("Account %q authenticated successfully from %s on %s after %d failures in the previous %s — possible successful brute force or spray.",
					o.user, o.ip, ev.Host, len(fails), authSuccessWindow),
				Severity: 5, MITRE: "T1110", Entity: "success|" + fk, Bucket: t.Unix() / int64(authSuccessWindow.Seconds()),
			})
			c.ipFails[fk] = nil
		}
	}
	return hits
}

// raiseAuthHits turns correlator hits into deduplicated alerts.
func sha12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

func (e *DetectionEngine) raiseAuthHits(ctx context.Context, ev store.Event, hits []authHit) {
	for _, h := range hits {
		a := store.Alert{
			Title: "[CORR] " + h.Title, Description: h.Desc + "\nRule: " + h.Rule + " (" + h.MITRE + ")",
			Severity: h.Severity, AgentID: ev.AgentID, Host: ev.Host, EventType: ev.EventType,
			EventID:       fmt.Sprintf("corr:%s:%s:%d", h.Rule, sha12(h.Entity), h.Bucket),
			SourceEventID: ev.ID,
		}
		if _, _, err := e.db.CreateAlertDeduped(ctx, a); err != nil {
			e.logger.Warn("auth correlation: alert failed", "rule", h.Rule, "err", err)
		}
	}
}
