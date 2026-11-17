package response

import (
	"fmt"
	"net/netip"
	"strings"
)

// pfRules builds a pf ruleset that drops everything except loopback, DHCP and
// the ObsidianWatch backend/management addresses.
func pfRules(allow []netip.Addr) string {
	var ips []string
	for _, a := range allow {
		ips = append(ips, a.String())
	}
	list := "{ " + strings.Join(ips, ", ") + " }"
	var b strings.Builder
	b.WriteString("# ObsidianWatch host isolation - do not edit\n")
	b.WriteString("set skip on lo0\n")
	b.WriteString("block drop all\n")
	b.WriteString("pass out quick inet proto udp from any port 68 to any port 67 keep state\n")
	b.WriteString("pass in quick inet proto udp from any port 67 to any port 68 keep state\n")
	fmt.Fprintf(&b, "pass out quick from any to %s keep state\n", list)
	fmt.Fprintf(&b, "pass in quick from %s to any keep state\n", list)
	return b.String()
}
