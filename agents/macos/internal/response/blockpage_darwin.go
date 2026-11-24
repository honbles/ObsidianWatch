//go:build darwin

package response

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// On macOS the block page listens on the standard loopback ports (pf skips
// lo0) and every enabled network service's DNS points at it while isolated.
func blockPageAddrs() (string, string) { return "127.0.0.1:80", "127.0.0.1:53" }

// networkServices lists enabled services from `networksetup -listallnetworkservices`.
func networkServices(out string) []string {
	var svcs []string
	for i, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if i == 0 || l == "" || strings.HasPrefix(l, "*") { // header line; "*" = disabled
			continue
		}
		svcs = append(svcs, l)
	}
	return svcs
}

// dnsServers parses `networksetup -getdnsservers`; nil means "not set" (DHCP).
func dnsServers(out string) []string {
	var s []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if _, err := netip.ParseAddr(l); err == nil {
			s = append(s, l)
		}
	}
	return s
}

func pointToBlockPage(saved string) (string, error) {
	ctx := context.Background()
	prev := map[string][]string{}
	if saved != "" {
		_ = json.Unmarshal([]byte(saved), &prev)
	}
	out, err := run(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return saved, fmt.Errorf("networksetup: %v: %s", err, out)
	}
	for _, svc := range networkServices(out) {
		if _, done := prev[svc]; !done {
			cur, _ := run(ctx, "networksetup", "-getdnsservers", svc)
			prev[svc] = dnsServers(cur)
		}
		if o, err := run(ctx, "networksetup", "-setdnsservers", svc, "127.0.0.1"); err != nil {
			return marshalDNS(prev), fmt.Errorf("networksetup -setdnsservers %s: %v: %s", svc, err, o)
		}
	}
	flushDNS(ctx)
	return marshalDNS(prev), nil
}

func marshalDNS(m map[string][]string) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func unpointBlockPage(saved string) error {
	ctx := context.Background()
	prev := map[string][]string{}
	if err := json.Unmarshal([]byte(saved), &prev); err != nil {
		return fmt.Errorf("unrecognised saved DNS settings: %v", err)
	}
	var errs []string
	for svc, servers := range prev {
		args := []string{"-setdnsservers", svc}
		if len(servers) == 0 {
			args = append(args, "Empty")
		} else {
			args = append(args, servers...)
		}
		if o, err := run(ctx, "networksetup", args...); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v: %s", svc, err, o))
		}
	}
	flushDNS(ctx)
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func flushDNS(ctx context.Context) {
	_, _ = run(ctx, "dscacheutil", "-flushcache")
	_, _ = run(ctx, "killall", "-HUP", "mDNSResponder")
}
