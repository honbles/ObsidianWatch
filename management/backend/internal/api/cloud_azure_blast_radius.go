package api

// cloud_azure_blast_radius.go — Azure resource relationship mapping and blast radius analysis.
//
// Builds a directed graph of Azure resource relationships:
//   ServicePrincipal → (has role) → Subscription/ResourceGroup
//   VM → (uses managed identity) → ManagedIdentity → RoleAssignments
//   StorageAccount → (public) → Internet
//   KeyVault → (no private endpoint) → Internet
//   NSG → (open rule) → Internet → VM
//   AKS cluster → (node pool SA) → ManagedIdentity
//
// Risk paths:
//   Internet → Open NSG port → VM → Managed Identity → Subscription Owner
//   Compromised SP → Owner role → All resources
//   Public storage → Data exfiltration

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RunAzureBlastRadius builds the resource relationship graph for an Azure subscription
func RunAzureBlastRadius(ctx context.Context, tenantID, clientID, clientSecret, subID string,
	cspm *AzureCSPMResult, connID int64) (*BlastRadiusResult, error) {

	start := time.Now()
	result := &BlastRadiusResult{
		ConnectorID: connID,
		ProjectID:   subID,
		ScannedAt:   start,
	}

	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
	if err != nil { return nil, fmt.Errorf("azure auth: %w", err) }
	t := token.AccessToken

	// Build finding index for risk annotation
	findingsByResource := make(map[string][]CSPMFinding)
	if cspm != nil {
		for _, f := range cspm.Findings {
			findingsByResource[f.Resource] = append(findingsByResource[f.Resource], f)
		}
	}

	nodes := make(map[string]*BlastNode)
	var edges []*BlastEdge

	addNode := func(id, name, fullName, typ string, props map[string]string) *BlastNode {
		if n, ok := nodes[id]; ok { return n }
		n := &BlastNode{ID: id, Name: name, FullName: fullName, Type: typ, Risk: "none", Properties: props}
		if findings, ok := findingsByResource[name]; ok && len(findings) > 0 {
			n.HasFindings = true
			n.FindingCount = len(findings)
			worst := findings[0].Severity
			for _, f := range findings {
				if f.Severity == "critical" { worst = "critical"; break }
				if f.Severity == "high" && worst != "critical" { worst = "high" }
			}
			n.Risk = worst
		}
		nodes[id] = n
		return n
	}

	addEdge := func(from, to, rel string, riskBoost bool) {
		for _, e := range edges {
			if e.From == from && e.To == to { return }
		}
		edges = append(edges, &BlastEdge{From: from, To: to, Relationship: rel, RiskBoost: riskBoost})
	}

	// ── Internet node (always present) ────────────────────────────────────────
	internet := addNode("internet:public", "Internet", "Public Internet", "internet", nil)
	_ = internet

	// ── 1. Role Assignments — build SP/User → Role → Scope edges ─────────────
	roleURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", subID)
	var roleResp struct {
		Value []struct {
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				PrincipalID      string `json:"principalId"`
				PrincipalType    string `json:"principalType"`
				Scope            string `json:"scope"`
			} `json:"properties"`
		} `json:"value"`
	}
	// Fetch role definition names
	roleDefsURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", subID)
	var roleDefsResp struct {
		Value []struct {
			ID         string `json:"id"`
			Properties struct{ RoleName string `json:"roleName"` } `json:"properties"`
		} `json:"value"`
	}
	roleNameMap := map[string]string{}
	if err := azureCSPMGet(ctx, t, roleDefsURL, &roleDefsResp); err == nil {
		for _, r := range roleDefsResp.Value {
			parts := strings.Split(r.ID, "/")
			if len(parts) > 0 { roleNameMap[parts[len(parts)-1]] = r.Properties.RoleName }
		}
	}
	if err := azureCSPMGet(ctx, t, roleURL, &roleResp); err == nil {
		privEscCount := 0
		for _, ra := range roleResp.Value {
			parts := strings.Split(ra.Properties.RoleDefinitionID, "/")
			roleID := ""
			if len(parts) > 0 { roleID = parts[len(parts)-1] }
			roleName := roleNameMap[roleID]
			if roleName == "" { continue }

			principalShort := ra.Properties.PrincipalID
			if len(principalShort) > 8 { principalShort = principalShort[:8] }

			principalID := fmt.Sprintf("principal:%s", ra.Properties.PrincipalID)
			principalType := strings.ToLower(ra.Properties.PrincipalType)
			if principalType == "serviceprincipal" { principalType = "service_account" }
			principalNode := addNode(principalID,
				fmt.Sprintf("%s:%s", ra.Properties.PrincipalType, principalShort),
				fmt.Sprintf("%s (principalId: %s)", ra.Properties.PrincipalType, ra.Properties.PrincipalID),
				principalType, map[string]string{"principal_type": ra.Properties.PrincipalType})

			roleNodeID := fmt.Sprintf("role:%s", roleID)
			roleNode := addNode(roleNodeID, fmt.Sprintf("roles/%s", roleName), roleName, "iam_role",
				map[string]string{"scope": ra.Properties.Scope})

			if roleName == "Owner" || roleName == "Contributor" {
				principalNode.Risk = "critical"
				if roleName == "Owner" { roleNode.Risk = "critical" } else { roleNode.Risk = "high" }
			}

			addEdge(principalID, roleNodeID, "has_role", roleName == "Owner" || roleName == "Contributor")

			// Owner/Contributor → sub root = high blast radius
			if (roleName == "Owner" || roleName == "Contributor") &&
				strings.HasSuffix(ra.Properties.Scope, "/subscriptions/"+subID) {
				subNode := addNode("subscription:"+subID, "Subscription", subID, "network",
					map[string]string{"sub": subID})
				subNode.Risk = "critical"
				addEdge(roleNodeID, "subscription:"+subID, "controls_all", true)
				privEscCount++
			}
		}
		result.Summary.PrivEscPaths = privEscCount
	} else {
		result.Errors = append(result.Errors, "role_assignments: "+err.Error())
	}

	// ── 2. VMs — identify public IPs and managed identities ──────────────────
	vmURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01", subID)
	var vmResp struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
			Identity *struct {
				Type string `json:"type"`
				PrincipalID string `json:"principalId"`
			} `json:"identity"`
			Properties struct {
				NetworkProfile struct {
					NetworkInterfaces []struct{ ID string `json:"id"` } `json:"networkInterfaces"`
				} `json:"networkProfile"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, t, vmURL, &vmResp); err == nil {
		for _, vm := range vmResp.Value {
			vmID := "vm:" + vm.Name
			vmNode := addNode(vmID, vm.Name, vm.ID, "vm", map[string]string{"location": vm.Location})

			// Managed Identity
			if vm.Identity != nil && vm.Identity.PrincipalID != "" {
				miID := fmt.Sprintf("principal:%s", vm.Identity.PrincipalID)
				miNode := addNode(miID,
					fmt.Sprintf("ManagedIdentity:%s", vm.Name),
					fmt.Sprintf("Managed Identity for VM %s", vm.Name),
					"service_account",
					map[string]string{"identity_type": vm.Identity.Type})
				addEdge(vmID, miID, "uses_managed_identity", false)

				// If MI has Owner/Contributor (detected in role assignments above)
				if miNode.Risk == "critical" || miNode.Risk == "high" {
					vmNode.Risk = miNode.Risk
					result.Summary.PrivEscPaths++
				}
			}
		}
	} else {
		result.Errors = append(result.Errors, "vms: "+err.Error())
	}

	// ── 3. NSGs — find open rules and connect to internet ────────────────────
	nsgURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01", subID)
	var nsgResp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Properties struct {
				SecurityRules []struct {
					Properties struct {
						SourceAddressPrefix  string `json:"sourceAddressPrefix"`
						DestinationPortRange string `json:"destinationPortRange"`
						Direction            string `json:"direction"`
						Access               string `json:"access"`
					} `json:"properties"`
				} `json:"securityRules"`
				Subnets []struct{ ID string `json:"id"` } `json:"subnets"`
			} `json:"properties"`
		} `json:"value"`
	}
	publicExposures := 0
	if err := azureCSPMGet(ctx, t, nsgURL, &nsgResp); err == nil {
		for _, nsg := range nsgResp.Value {
			nsgID := "nsg:" + nsg.Name
			nsgNode := addNode(nsgID, nsg.Name, nsg.ID, "firewall", nil)
			hasOpenRule := false
			for _, rule := range nsg.Properties.SecurityRules {
				rp := rule.Properties
				if rp.Direction != "Inbound" || rp.Access != "Allow" { continue }
				isOpen := rp.SourceAddressPrefix == "*" || rp.SourceAddressPrefix == "0.0.0.0/0" ||
					rp.SourceAddressPrefix == "Internet" || rp.SourceAddressPrefix == "Any"
				if isOpen {
					hasOpenRule = true
					publicExposures++
					nsgNode.Risk = "high"
					nsgNode.HasFindings = true
					addEdge("internet:public", nsgID, "can_reach_via_port_"+rp.DestinationPortRange, true)
				}
			}
			if hasOpenRule {
				// Connect NSG to subnet/VMs if possible
				for _, subnet := range nsg.Properties.Subnets {
					subnetShort := subnet.ID[strings.LastIndex(subnet.ID, "/")+1:]
					subnetNodeID := "subnet:" + subnetShort
					addNode(subnetNodeID, subnetShort, subnet.ID, "network", nil)
					addEdge(nsgID, subnetNodeID, "protects", false)
				}
			}
		}
	} else {
		result.Errors = append(result.Errors, "nsgs: "+err.Error())
	}
	result.Summary.PublicExposures = publicExposures

	// ── 4. Storage Accounts — public access ───────────────────────────────────
	storageURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", subID)
	var storageResp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Properties struct {
				AllowBlobPublicAccess *bool `json:"allowBlobPublicAccess"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, t, storageURL, &storageResp); err == nil {
		for _, sa := range storageResp.Value {
			saID := "storage:" + sa.Name
			saNode := addNode(saID, sa.Name, sa.ID, "storage_bucket", nil)
			if sa.Properties.AllowBlobPublicAccess == nil || *sa.Properties.AllowBlobPublicAccess {
				saNode.Risk = "high"
				saNode.HasFindings = true
				addEdge("internet:public", saID, "public_blob_access", true)
				result.Summary.PublicExposures++
			}
		}
	} else {
		result.Errors = append(result.Errors, "storage: "+err.Error())
	}

	// ── 5. Key Vaults — public access ─────────────────────────────────────────
	kvURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01", subID)
	var kvResp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Properties struct {
				PublicNetworkAccess string `json:"publicNetworkAccess"`
				NetworkAcls *struct {
					DefaultAction string `json:"defaultAction"`
				} `json:"networkAcls"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, t, kvURL, &kvResp); err == nil {
		for _, kv := range kvResp.Value {
			kvID := "keyvault:" + kv.Name
			kvNode := addNode(kvID, kv.Name, kv.ID, "secret", map[string]string{"type": "key_vault"})
			isPublic := kv.Properties.PublicNetworkAccess == "Enabled" || kv.Properties.PublicNetworkAccess == ""
			if kv.Properties.NetworkAcls != nil && kv.Properties.NetworkAcls.DefaultAction == "Allow" {
				isPublic = true
			}
			if isPublic {
				kvNode.Risk = "medium"
				addEdge("internet:public", kvID, "public_network_access", false)
			}
			// Connect to subscription — KV compromise = credential theft = subscription access
			addEdge(kvID, "subscription:"+subID, "contains_secrets_for", true)
		}
	} else {
		result.Errors = append(result.Errors, "keyvaults: "+err.Error())
	}

	// ── Build high-risk paths ──────────────────────────────────────────────────
	var highRiskPaths []BlastPath
	criticalPaths := 0

	// Path 1: Internet → Open NSG → VM → Managed Identity → Owner role
	for _, n := range nodes {
		if n.Type == "vm" && (n.Risk == "critical" || n.Risk == "high") {
			// Check if internet can reach this VM via NSG
			vmReachable := false
			for _, e := range edges {
				if e.To == "nsg:"+strings.TrimPrefix(n.ID, "vm:") { vmReachable = true }
				if strings.HasPrefix(e.From, "internet") { vmReachable = true }
			}
			if vmReachable && n.Risk == "critical" {
				highRiskPaths = append(highRiskPaths, BlastPath{
					StartNode:    "internet:public",
					Path:         []string{"internet:public", n.ID, "managed_identity", "subscription_owner"},
					EndPrivilege: "project_owner",
					Severity:     "critical",
					Description:  fmt.Sprintf("Internet → Open NSG → VM '%s' → Managed Identity → Owner/Contributor role on subscription. Full subscription compromise via network path.", strings.TrimPrefix(n.ID, "vm:")),
				})
				criticalPaths++
			}
		}
	}

	// Path 2: Service Principal with Owner role
	for _, n := range nodes {
		if (n.Type == "service_account" || n.Type == "user") && n.Risk == "critical" {
			highRiskPaths = append(highRiskPaths, BlastPath{
				StartNode:    n.ID,
				Path:         []string{n.ID, "roles/Owner", "subscription:" + subID},
				EndPrivilege: "project_owner",
				Severity:     "critical",
				Description:  fmt.Sprintf("Principal '%s' has Owner role at subscription scope — full control over all Azure resources, ability to create/delete resources, modify IAM, access all secrets.", n.Name),
			})
			criticalPaths++
		}
	}

	// Path 3: Public storage = data exfiltration
	for _, n := range nodes {
		if n.Type == "storage_bucket" && n.Risk != "none" {
			highRiskPaths = append(highRiskPaths, BlastPath{
				StartNode:    "internet:public",
				Path:         []string{"internet:public", n.ID},
				EndPrivilege: "all_data",
				Severity:     "high",
				Description:  fmt.Sprintf("Storage account '%s' allows public blob access — any unauthenticated user can read all blob data in any public container.", strings.TrimPrefix(n.ID, "storage:")),
			})
		}
	}

	// Collect into result
	nodeSlice := make([]BlastNode, 0, len(nodes))
	highRiskCount := 0
	for _, n := range nodes {
		nodeSlice = append(nodeSlice, *n)
		if n.Risk == "critical" || n.Risk == "high" { highRiskCount++ }
	}
	edgeSlice := make([]BlastEdge, 0, len(edges))
	for _, e := range edges { edgeSlice = append(edgeSlice, *e) }

	result.Nodes = nodeSlice
	result.Edges = edgeSlice
	result.HighRiskPaths = highRiskPaths
	result.Summary.TotalNodes = len(nodeSlice)
	result.Summary.TotalEdges = len(edgeSlice)
	result.Summary.HighRiskNodes = highRiskCount
	result.Summary.CriticalPaths = criticalPaths

	return result, nil
}

// marshalAzureBlast is a helper for testing
func marshalAzureBlast(r *BlastRadiusResult) ([]byte, error) {
	return json.Marshal(r)
}
