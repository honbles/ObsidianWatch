package api

// G-44: additional GCP CSPM checks — default network, HTTPS load balancer
// minimum TLS, and DNSSEC on public Cloud DNS zones.

import (
	"context"
	"fmt"
	"strings"
)

func checkDefaultNetwork(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/global/networks", projectID)
	var resp struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}
	for _, n := range resp.Items {
		if n.Name == "default" {
			return []CSPMFinding{{
				Title:        "The default VPC network exists",
				Description:  "The auto-created 'default' network has permissive pre-populated firewall rules (SSH, RDP, ICMP from anywhere) and an auto-mode subnet in every region.",
				Severity:     "medium",
				Category:     "network",
				Resource:     "default",
				ResourceType: "vpc_network",
				Remediation:  "Create purpose-built VPCs with custom subnets and delete the default network (CIS GCP 3.1).",
				MITRE:        "T1190",
			}}, 0, nil
		}
	}
	return nil, 1, nil
}

func checkHTTPSLBTLS(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	var proxies struct {
		Items []struct {
			Name      string `json:"name"`
			SslPolicy string `json:"sslPolicy"`
		} `json:"items"`
	}
	base := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/global", projectID)
	if err := gcpCSPMGet(ctx, token, base+"/targetHttpsProxies", &proxies); err != nil {
		return nil, 0, err
	}
	var pol struct {
		Items []struct {
			Name          string `json:"name"`
			MinTLSVersion string `json:"minTlsVersion"`
			Profile       string `json:"profile"`
		} `json:"items"`
	}
	minTLS := map[string]string{}
	if err := gcpCSPMGet(ctx, token, base+"/sslPolicies", &pol); err == nil {
		for _, p := range pol.Items {
			minTLS[p.Name] = p.MinTLSVersion
		}
	}
	var findings []CSPMFinding
	passed := 0
	for _, p := range proxies.Items {
		policy := p.SslPolicy[strings.LastIndex(p.SslPolicy, "/")+1:]
		v := ""
		if policy != "" {
			v = minTLS[policy]
		}
		if policy == "" || v == "TLS_1_0" || v == "TLS_1_1" {
			why := "no SSL policy attached (GCP default allows TLS 1.0)"
			if policy != "" {
				why = fmt.Sprintf("SSL policy '%s' allows %s", policy, v)
			}
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("HTTPS load balancer proxy '%s' accepts TLS older than 1.2", p.Name),
				Description:  "Old TLS versions have known weaknesses. " + why + ".",
				Severity:     "medium",
				Category:     "network",
				Resource:     p.Name,
				ResourceType: "target_https_proxy",
				Remediation:  "Create an SSL policy with minTlsVersion TLS_1_2 and profile MODERN or RESTRICTED, and attach it to the proxy.",
				MITRE:        "T1040",
			})
		} else {
			passed++
		}
	}
	return findings, passed, nil
}

func checkDNSSEC(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://dns.googleapis.com/dns/v1/projects/%s/managedZones", projectID)
	var resp struct {
		ManagedZones []struct {
			Name         string `json:"name"`
			DNSName      string `json:"dnsName"`
			Visibility   string `json:"visibility"`
			DnssecConfig *struct {
				State string `json:"state"`
			} `json:"dnssecConfig"`
		} `json:"managedZones"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}
	var findings []CSPMFinding
	passed := 0
	for _, z := range resp.ManagedZones {
		if z.Visibility != "" && z.Visibility != "public" {
			continue
		}
		if z.DnssecConfig == nil || z.DnssecConfig.State != "on" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("DNSSEC is not enabled on public zone '%s'", z.DNSName),
				Description:  "Without DNSSEC, resolvers cannot verify DNS answers for this zone, leaving it open to cache poisoning and spoofing.",
				Severity:     "medium",
				Category:     "network",
				Resource:     z.Name,
				ResourceType: "dns_zone",
				Remediation:  "Enable DNSSEC on the zone and publish the DS record at the registrar (CIS GCP 3.3).",
				MITRE:        "T1584.002",
			})
		} else {
			passed++
		}
	}
	return findings, passed, nil
}
