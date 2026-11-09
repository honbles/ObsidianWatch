//go:build linux

package collector

import "testing"

func TestParseDpkgLine(t *testing.T) {
	ch, ok := parseDpkgLine("2026-11-08 10:00:00 install nmap:amd64 <none> 7.94")
	if !ok || ch.Action != "software_installed" || ch.Package != "nmap" || ch.Version != "7.94" {
		t.Fatalf("install: %+v %v", ch, ok)
	}
	ch, ok = parseDpkgLine("2026-11-08 10:00:00 remove nmap:amd64 7.94 7.94")
	if !ok || ch.Action != "software_removed" || ch.Package != "nmap" {
		t.Fatalf("remove: %+v %v", ch, ok)
	}
	for _, l := range []string{"2026-11-08 10:00:00 status installed nmap:amd64 7.94", "", "short line"} {
		if _, ok := parseDpkgLine(l); ok {
			t.Fatalf("should ignore %q", l)
		}
	}
}

func TestRiskOf(t *testing.T) {
	var d dockerInspect
	d.ID, d.Name = "abc", "/web"
	d.HostConfig.Privileged = true
	d.HostConfig.NetworkMode = "host"
	d.HostConfig.Binds = []string{"/var/run/docker.sock:/var/run/docker.sock"}
	ci := riskOf(d)
	if ci.Name != "web" || len(ci.Risks) != 3 || !ci.SockMount {
		t.Fatalf("%+v", ci)
	}
	if len(riskOf(dockerInspect{}).Risks) != 0 {
		t.Fatal("clean container flagged")
	}
}
