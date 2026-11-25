//go:build linux && netnslive

package response

// Live check of isolation + block page against the real kernel firewall.
// Run as root inside a throwaway network namespace, e.g.:
//
//	go test -c -tags netnslive -o /tmp/resp.test ./internal/response
//	unshare -n sh -c 'ip link set lo up; ip addr add 10.9.9.9/32 dev lo; ip route add default dev lo src 10.9.9.9;
//	  /tmp/resp.test -test.run LiveBlockPage -test.v & sleep 1;
//	  curl -s http://10.9.9.77/ | grep -c "contact your administrator"; wait'
//
// With nft hidden from PATH the iptables path is exercised instead.

import (
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLiveBlockPageNetns(t *testing.T) {
	allow := []netip.Addr{netip.MustParseAddr("10.9.9.50")}
	saved, err := applyIsolation(allow, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("firewall:", saved)
	var bp blockPage
	h, d := blockPageAddrs()
	if _, err := bp.start(h, d, map[string][]netip.Addr{"siem.corp": {allow[0]}}, "netns-host"); err != nil {
		t.Fatal(err)
	}
	wait := 8 * time.Second
	if v, err := time.ParseDuration(os.Getenv("OW_LIVE_WAIT")); err == nil {
		wait = v
	}
	time.Sleep(wait)
	bp.stop()
	if err := removeIsolation(saved); err != nil {
		t.Fatal(err)
	}
}

// TestLiveIPBlockAndUser blocks one address and locks a throwaway account
// (OW_LIVE_USER, created by the caller) on the real system.
func TestLiveIPBlockAndUser(t *testing.T) {
	h := New(t.TempDir(), []string{"https://10.9.9.50:8443"}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if r := h.blockIP("10.9.9.77"); !r.OK {
		t.Fatal(r.Message)
	}
	os.WriteFile("/tmp/bptest/ready", []byte("1"), 0o644)
	time.Sleep(4 * time.Second)
	if r := h.unblockIP("10.9.9.77"); !r.OK {
		t.Fatal(r.Message)
	}
	if u := os.Getenv("OW_LIVE_USER"); u != "" {
		r := h.disableUserAction(u)
		if !r.OK {
			t.Fatal(r.Message)
		}
		t.Log(r.Message)
		out, _ := exec.Command("chage", "-l", u).CombinedOutput()
		t.Log(string(out))
		t.Log(h.enableUserAction(u).Message)
		out, _ = exec.Command("chage", "-l", u).CombinedOutput()
		t.Log(string(out))
	}
}
