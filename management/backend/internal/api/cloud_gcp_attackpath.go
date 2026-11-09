package api

import "strings"

// GR-03: the blast-radius graph names a service account twice — "sa:<email>"
// when a VM runs as it, and "principal:serviceAccount:<email>" when an IAM
// binding grants it a role. Without a link between the two, a path such as
//
//	internet -> public VM -> its service account -> roles/owner
//
// is never found, because the walk stops at the VM-side node. linkSAIdentities
// joins the two views so exposure, impersonation and privilege edges chain.
func linkSAIdentities(nodes map[string]*BlastNode, edges []*BlastEdge) []*BlastEdge {
	have := make(map[string]bool, len(edges))
	for _, e := range edges {
		have[e.From+"|"+e.To+"|"+e.Relationship] = true
	}
	var added []*BlastEdge
	for id := range nodes {
		if !strings.HasPrefix(id, "sa:") {
			continue
		}
		email := strings.TrimPrefix(id, "sa:")
		pid := "principal:serviceAccount:" + email
		if _, ok := nodes[pid]; !ok {
			continue
		}
		key := id + "|" + pid + "|is_identity"
		if have[key] {
			continue
		}
		have[key] = true
		added = append(added, &BlastEdge{From: id, To: pid, Relationship: "is_identity", RiskBoost: true})
	}
	return added
}
