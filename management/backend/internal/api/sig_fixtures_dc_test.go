package api

// Domain controller and DNS-category fixtures.

import "obsidianwatch/management/internal/store"

func fxStrp(s string) *string { return &s }
func fxU32p(v uint32) *uint32 { return &v }

func fxKerb(id uint32, proc string, sev int) store.Event {
	return store.Event{EventType: "kerberos", EventID: fxU32p(id), ProcessName: fxStrp(proc), Severity: sev}
}

func fxAD(id uint32, path string) store.Event {
	return store.Event{EventType: "ad_change", EventID: fxU32p(id), FilePath: fxStrp(path)}
}

func fxDCSync(user string) store.Event {
	return store.Event{EventType: "ad_object_access", CommandLine: fxStrp("Properties: 1131f6aa 19195a5b DS-Replication-Get-Changes"), UserName: fxStrp(user)}
}

func init() {
	dnsCatCache["c2.bad.test"] = []string{"botnet_cc"}
	dnsCatCache["phish.bad.test"] = []string{"phishing"}
	dnsCatCache["mal.bad.test"] = []string{"malicious"}
	dnsCatCache["spam.bad.test"] = []string{"spam"}
	dnsCatCache["good.example.test"] = []string{"cdn"}

	adm := fxKerb(4728, "Domain Admins", 1)
	adm.EventID = fxU32p(4728)
	sigFixtures = append(sigFixtures, []sigFixture{
		{"DC-T1003.006", fxDCSync("attacker"), fxDCSync("DC02$")},
		{"DC-T1558.003", fxKerb(4769, "svc-sql", 1), fxKerb(4769, "DC01$", 1)},
		{"DC-T1558.004", fxKerb(4768, "alice", 3), fxKerb(4768, "alice", 1)},
		{"DC-T1558.001", fxKerb(4769, "krbtgt", 1), fxKerb(4768, "krbtgt", 1)},
		{"DC-T1484.001", fxAD(4739, ""), fxAD(5136, "")},
		{"DC-T1078.002", fxAD(5136, "CN=AdminSDHolder,CN=System"), fxAD(5136, "CN=Users,DC=corp")},
		{"DC-T1484.001b", fxAD(5136, "CN=Policies,CN=GroupPolicyContainer"), fxAD(5136, "CN=Users,DC=corp")},
		{"DC-T1136.002", store.Event{EventType: "ad_change", EventID: fxU32p(4728), ProcessName: fxStrp("Domain Admins")}, store.Event{EventType: "ad_change", EventID: fxU32p(4728), ProcessName: fxStrp("Print Operators")}},
		{"DC-T1110.003", fxKerb(4771, "alice", 1), fxKerb(4768, "alice", 1)},
		{"DNS-CAT-001", fxDNSEvent("c2.bad.test"), fxDNSEvent("good.example.test")},
		{"DNS-CAT-002", fxDNSEvent("phish.bad.test"), fxDNSEvent("good.example.test")},
		{"DNS-CAT-003", fxDNSEvent("mal.bad.test"), fxDNSEvent("good.example.test")},
		{"DNS-CAT-004", fxDNSEvent("spam.bad.test"), fxDNSEvent("good.example.test")},
	}...)
}
