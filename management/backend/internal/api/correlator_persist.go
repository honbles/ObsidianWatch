package api

// D-07: correlator state survives restarts. The sliding-window state of the
// auth and sequence correlators is snapshotted to the settings table after
// each evaluation cycle (when it changed) and restored once at startup, so a
// restart no longer forgets in-progress brute-force windows or half-complete
// sequences. Stale entries are dropped on restore.

import (
	"context"
	"encoding/json"
	"time"

	"obsidianwatch/management/internal/store"
)

const correlatorStateKey = "correlator.state.v1"

type authFailRecJSON struct {
	T time.Time `json:"t"`
	U string    `json:"u"`
}

type correlatorSnapshot struct {
	SavedAt time.Time                    `json:"saved_at"`
	ByIP    map[string][]authFailRecJSON `json:"by_ip"`
	ByUser  map[string][]time.Time       `json:"by_user"`
	IPFails map[string][]time.Time       `json:"ip_fails"`
	MFA     map[string][]time.Time       `json:"mfa"`
	Seq     map[string]time.Time         `json:"seq"`
}

const correlatorMaxAge = 2 * time.Hour // longest window we keep is far shorter

func (c *authCorrelator) snapshotInto(s *correlatorSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s.ByIP = map[string][]authFailRecJSON{}
	for k, v := range c.byIP {
		for _, r := range v {
			s.ByIP[k] = append(s.ByIP[k], authFailRecJSON{T: r.t, U: r.user})
		}
	}
	s.ByUser, s.IPFails, s.MFA = map[string][]time.Time{}, map[string][]time.Time{}, map[string][]time.Time{}
	for k, v := range c.byUser {
		s.ByUser[k] = append([]time.Time(nil), v...)
	}
	for k, v := range c.ipFails {
		s.IPFails[k] = append([]time.Time(nil), v...)
	}
	for k, v := range c.mfa {
		s.MFA[k] = append([]time.Time(nil), v...)
	}
}

func freshTimes(ts []time.Time, cut time.Time) []time.Time {
	var out []time.Time
	for _, t := range ts {
		if !t.Before(cut) {
			out = append(out, t)
		}
	}
	return out
}

func (c *authCorrelator) restoreFrom(s correlatorSnapshot, now time.Time) {
	cut := now.Add(-correlatorMaxAge)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range s.ByIP {
		for _, r := range v {
			if !r.T.Before(cut) {
				c.byIP[k] = append(c.byIP[k], authFailRec{t: r.T, user: r.U})
			}
		}
	}
	for k, v := range s.ByUser {
		if f := freshTimes(v, cut); len(f) > 0 {
			c.byUser[k] = f
		}
	}
	for k, v := range s.IPFails {
		if f := freshTimes(v, cut); len(f) > 0 {
			c.ipFails[k] = f
		}
	}
	for k, v := range s.MFA {
		if f := freshTimes(v, cut); len(f) > 0 {
			c.mfa[k] = f
		}
	}
}

func (c *seqCorrelator) snapshotInto(s *correlatorSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s.Seq = make(map[string]time.Time, len(c.state))
	for k, v := range c.state {
		s.Seq[k] = v
	}
}

func (c *seqCorrelator) restoreFrom(s correlatorSnapshot, now time.Time) {
	cut := now.Add(-correlatorMaxAge)
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range s.Seq {
		if !v.Before(cut) {
			c.state[k] = v
		}
	}
}

func saveCorrelatorState(ctx context.Context, db *store.DB, a *authCorrelator, q *seqCorrelator) {
	var s correlatorSnapshot
	s.SavedAt = time.Now().UTC()
	a.snapshotInto(&s)
	q.snapshotInto(&s)
	b, err := json.Marshal(s)
	if err != nil || len(b) > 4<<20 {
		return
	}
	_ = db.SetSetting(ctx, correlatorStateKey, string(b))
}

func loadCorrelatorState(ctx context.Context, db *store.DB, a *authCorrelator, q *seqCorrelator) {
	v, err := db.GetSetting(ctx, correlatorStateKey)
	if err != nil || v == "" {
		return
	}
	var s correlatorSnapshot
	if json.Unmarshal([]byte(v), &s) != nil {
		return
	}
	now := time.Now()
	a.restoreFrom(s, now)
	q.restoreFrom(s, now)
}
