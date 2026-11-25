package response

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestIsolationNotices(t *testing.T) {
	var mu sync.Mutex
	var got []string
	n := &noticer{show: func(title, msg string) {
		mu.Lock()
		got = append(got, title)
		mu.Unlock()
	}}
	count := func() int {
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return len(got)
	}
	n.attempt() // not isolated: nothing
	if count() != 0 {
		t.Fatal("notice while not isolated")
	}
	n.isolated()
	n.attempt() // within the interval: no repeat
	if count() != 1 {
		t.Fatalf("got %v", got)
	}
	n.mu.Lock()
	n.last = time.Now().Add(-noticeEvery - time.Second)
	n.mu.Unlock()
	n.attempt()
	if count() != 2 {
		t.Fatalf("browse attempt after the interval: %v", got)
	}
	n.released()
	n.released() // only once
	if count() != 3 {
		t.Fatalf("release: %v", got)
	}
	n.resume() // agent restarted while isolated: next attempt shows
	n.attempt()
	if count() != 4 {
		t.Fatalf("resume: %v", got)
	}
}

func TestSinkLookupTriggersNotice(t *testing.T) {
	hits := 0
	b := &blockPage{exempt: map[string][]netip.Addr{}, onSink: func() { hits++ }}
	b.lookupNoted("claude.ai")
	if hits != 1 {
		t.Fatal("sunk lookup did not trigger")
	}
}
