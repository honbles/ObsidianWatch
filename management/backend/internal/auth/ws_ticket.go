package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// WebSocket tickets: browsers cannot set an Authorization header on a
// WebSocket, and putting the long-lived JWT in the URL leaks it into proxy and
// access logs. Instead the client POSTs (authenticated) for a ticket that is
// valid for a few seconds, usable once, and only accepted on WebSocket paths.

const (
	wsTicketTTL = 30 * time.Second
	wsTicketMax = 10000
)

// wsPaths are the only paths a ticket can authenticate.
var wsPaths = map[string]bool{
	"/ws/events":                     true,
	"/api/v1/live-response/terminal": true,
}

type ticketEntry struct {
	claims  Claims
	expires time.Time
}

var (
	ticketMu sync.Mutex
	tickets  = map[string]ticketEntry{}
)

// IssueWSTicket mints a single-use ticket carrying the caller's claims.
func IssueWSTicket(c *Claims) (string, bool) {
	if c == nil {
		return "", false
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	ticketMu.Lock()
	defer ticketMu.Unlock()
	if len(tickets) >= wsTicketMax {
		for k, v := range tickets { // drop expired first
			if now.After(v.expires) {
				delete(tickets, k)
			}
		}
		if len(tickets) >= wsTicketMax {
			return "", false
		}
	}
	tickets[t] = ticketEntry{claims: *c, expires: now.Add(wsTicketTTL)}
	return t, true
}

// redeemWSTicket consumes a ticket, returning its claims if still valid.
func redeemWSTicket(t string) *Claims {
	if t == "" {
		return nil
	}
	ticketMu.Lock()
	e, ok := tickets[t]
	delete(tickets, t)
	ticketMu.Unlock()
	if !ok || time.Now().After(e.expires) {
		return nil
	}
	c := e.claims
	return &c
}
