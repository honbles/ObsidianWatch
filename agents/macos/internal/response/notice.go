package response

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Isolation notices: a desktop pop-up (not a web page) telling the user the
// computer is isolated. Shown when isolation starts, again when someone
// tries to reach a site while isolated (a DNS lookup answered by the sink),
// at most once per noticeEvery, and once on release. Isolation with
// no_block_page shows none.

const noticeEvery = 10 * time.Minute

const (
	noticeTitle    = "ObsidianWatch: computer isolated"
	noticeIsolated = "This computer (%s) has been isolated from the network by your security team. " +
		"Internet and network access are blocked. Contact your administrator."
	noticeReleased = "This computer (%s) is no longer isolated. Network access has been restored."
)

type noticer struct {
	mu   sync.Mutex
	last time.Time
	on   bool
	show func(title, msg string) // per OS; nil in tests
}

func hostLabel() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "this computer"
	}
	return h
}

func (n *noticer) isolated() {
	n.mu.Lock()
	n.on, n.last = true, time.Now()
	n.mu.Unlock()
	n.send(noticeTitle, sprintf(noticeIsolated, hostLabel()))
}

// attempt is called for every lookup the sink answers; it shows the notice
// again when the last one is older than noticeEvery.
func (n *noticer) attempt() {
	n.mu.Lock()
	if !n.on || time.Since(n.last) < noticeEvery {
		n.mu.Unlock()
		return
	}
	n.last = time.Now()
	n.mu.Unlock()
	n.send(noticeTitle, sprintf(noticeIsolated, hostLabel()))
}

// resume turns browse-attempt notices back on after an agent restart while
// the host stays isolated (no pop-up now; the next attempt shows one).
func (n *noticer) resume() {
	n.mu.Lock()
	n.on, n.last = true, time.Time{}
	n.mu.Unlock()
}

func (n *noticer) released() {
	n.mu.Lock()
	was := n.on
	n.on = false
	n.mu.Unlock()
	if was {
		n.send("ObsidianWatch: isolation lifted", sprintf(noticeReleased, hostLabel()))
	}
}

func (n *noticer) send(title, msg string) {
	if n.show != nil {
		go n.show(title, msg)
	}
}

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }
