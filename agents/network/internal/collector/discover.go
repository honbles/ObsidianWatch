package collector

// discover.go — SNMP subnet auto-discovery
// Scans a CIDR subnet, probes port 161, tries SNMP GET on sysName.
// Returns a list of responding devices with their labels.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/gosnmp/gosnmp"

	"obsidianwatch/network-probe/internal/config"
)

// DiscoverSNMP scans subnet and returns all SNMP-responsive hosts
func DiscoverSNMP(ctx context.Context, subnet, community string, logger *slog.Logger) []config.SNMPTarget {
	if community == "" {
		community = "public"
	}

	ips, err := hostsInCIDR(subnet)
	if err != nil {
		logger.Warn("discover: invalid subnet", "subnet", subnet, "err", err)
		return nil
	}

	logger.Info("discover: scanning", "subnet", subnet, "hosts", len(ips))

	results := make(chan config.SNMPTarget, len(ips))
	sem := make(chan struct{}, 50) // 50 concurrent probes

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break
		default:
		}
		ip := ip
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			if t, ok := probeSNMP(ctx, ip, community); ok {
				results <- t
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}
	close(results)

	var targets []config.SNMPTarget
	for t := range results {
		targets = append(targets, t)
	}
	logger.Info("discover: complete", "found", len(targets))
	return targets
}

// probeSNMP tries to SNMP GET sysName from a host
func probeSNMP(ctx context.Context, ip, community string) (config.SNMPTarget, bool) {
	g := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   1 * time.Second,
		Retries:   0,
		Logger:    gosnmp.NewLogger(noopLogger{}),
	}

	// Quick TCP check first to avoid timeout on every non-SNMP host
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:161", ip), 500*time.Millisecond)
	if err != nil {
		return config.SNMPTarget{}, false
	}
	conn.Close()

	if err := g.Connect(); err != nil {
		return config.SNMPTarget{}, false
	}
	defer g.Conn.Close()

	result, err := g.Get([]string{
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.1.0", // sysDescr
	})
	if err != nil {
		return config.SNMPTarget{}, false
	}

	name := ip
	descr := ""
	for _, v := range result.Variables {
		if b, ok := v.Value.([]byte); ok {
			switch v.Name {
			case ".1.3.6.1.2.1.1.5.0":
				name = string(b)
			case ".1.3.6.1.2.1.1.1.0":
				descr = string(b)
				if len(descr) > 40 {
					descr = descr[:40]
				}
			}
		}
	}

	if name == "" {
		name = ip
	}

	label := name
	if descr != "" {
		label = fmt.Sprintf("%s (%s)", name, descr)
		if len(label) > 40 {
			label = name
		}
	}

	return config.SNMPTarget{
		Host:      ip,
		Port:      161,
		Version:   "v2c",
		Community: community,
		Label:     label,
	}, true
}

// hostsInCIDR returns all host IPs in a CIDR range (excludes network + broadcast)
func hostsInCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := cloneIP(ipNet.IP); ipNet.Contains(ip); incrementIP(ip) {
		// Skip network address and broadcast
		if ip.Equal(ipNet.IP) {
			continue
		}
		broadcast := broadcastIP(ipNet)
		if ip.Equal(broadcast) {
			continue
		}
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func broadcastIP(n *net.IPNet) net.IP {
	broadcast := make(net.IP, len(n.IP))
	for i := range n.IP {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast
}
