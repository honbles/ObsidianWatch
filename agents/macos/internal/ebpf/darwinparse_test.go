package ebpf

import (
	"testing"
	"time"
)

func TestParsePS(t *testing.T) {
	out := "  1     0 root     Mon Nov  3 08:00:00 2026 /sbin/launchd\n" +
		"412     1 deploy   Wed Nov 18 07:00:00 2026 /usr/bin/java -jar /srv/orders/orders.jar --port 8080\n" +
		"garbage line\n"
	m := parsePS(out, time.UTC)
	j := m[412]
	if j.PPID != 1 || j.User != "deploy" || j.Exe != "/usr/bin/java" || j.Name != "java" || len(j.Args) != 4 || j.Start.Year() != 2026 {
		t.Fatalf("parsed: %+v", j)
	}
	if len(m) != 2 {
		t.Fatalf("want 2 rows, got %d", len(m))
	}
}

func TestParseLsofTCP(t *testing.T) {
	out := "p412\nf12\nn*:8080\nTST=LISTEN\nf15\nn10.0.0.5:55000->203.0.113.9:443\nTST=ESTABLISHED\np77\nf3\nn[::1]:5432\nTST=LISTEN\n"
	c := parseLsofTCP(out)
	if len(c) != 3 {
		t.Fatalf("rows: %+v", c)
	}
	if c[0].State != "LISTEN" || c[0].LocalPort != 8080 || c[0].PID != 412 || c[0].LocalIP != "0.0.0.0" {
		t.Errorf("listener: %+v", c[0])
	}
	if c[1].State != "ESTABLISHED" || c[1].RemoteIP != "203.0.113.9" || c[1].RemotePort != 443 || c[1].LocalPort != 55000 {
		t.Errorf("connection: %+v", c[1])
	}
	if c[2].PID != 77 || c[2].LocalIP != "::1" || c[2].LocalPort != 5432 {
		t.Errorf("ipv6 listener: %+v", c[2])
	}
}
