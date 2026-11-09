package api

// AW-10: account/regional service state — GuardDuty, Config, Security Hub, VPC
// flow logs, public EBS snapshots, default security groups, KMS key rotation.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func awsRESTGet(ctx context.Context, creds awsCreds, service, host, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+path, nil)
	if err != nil {
		return nil, 0, err
	}
	awsSign(req, creds, service, nil)
	resp, err := awsClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, resp.StatusCode, nil
}

// awsJSONPost issues an AWS JSON-1.1 call (target = "Service.Operation").
func awsJSONPost(ctx context.Context, creds awsCreds, service, host, target, body string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+host+"/", strings.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	awsSign(req, creds, service, []byte(body))
	resp, err := awsClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, resp.StatusCode, nil
}

func awsGuardDutyFinding(status int, body []byte, region string) *CSPMFinding {
	if status != 200 {
		return nil
	}
	var r struct {
		IDs []string `json:"detectorIds"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.IDs) > 0 {
		return nil
	}
	return &CSPMFinding{Title: "GuardDuty is not enabled in " + region, Severity: "medium", Category: "logging",
		Resource: "guardduty " + region, ResourceType: "account_setting", MITRE: "T1562.001",
		Description: "No GuardDuty detector exists in this region, so AWS managed threat detection is off.",
		Remediation: "Enable GuardDuty (ideally in every region, delegated to a security account)."}
}

func awsConfigRecorderFinding(status int, body []byte, region string) *CSPMFinding {
	if status != 200 {
		return nil
	}
	var r struct {
		Recorders []json.RawMessage `json:"ConfigurationRecorders"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.Recorders) > 0 {
		return nil
	}
	return &CSPMFinding{Title: "AWS Config recorder is not set up in " + region, Severity: "low", Category: "logging",
		Resource: "config " + region, ResourceType: "account_setting", MITRE: "T1562.008",
		Description: "Without a Config recorder there is no history of resource configuration changes in this region.",
		Remediation: "Create a configuration recorder and delivery channel (record all resources, including global ones in one region)."}
}

func awsSecurityHubFinding(status int, body []byte, region string) *CSPMFinding {
	if status == 200 {
		return nil
	}
	if (status == 401 || status == 403) && strings.Contains(string(body), "InvalidAccessException") {
		return &CSPMFinding{Title: "Security Hub is not enabled in " + region, Severity: "low", Category: "logging",
			Resource: "securityhub " + region, ResourceType: "account_setting", MITRE: "T1562.001",
			Description: "Security Hub aggregates findings and runs standard control checks; it is not enabled here.",
			Remediation: "Enable Security Hub with the AWS Foundational Security Best Practices standard."}
	}
	return nil
}

func awsFlowLogFindings(vpcsXML, flowXML []byte, region string) []CSPMFinding {
	var vpcs struct {
		Items []struct {
			ID      string `xml:"vpcId"`
			Default bool   `xml:"isDefault"`
		} `xml:"vpcSet>item"`
	}
	var fl struct {
		VPCs []string `xml:"flowLogSet>item>resourceId"`
	}
	if xml.Unmarshal(vpcsXML, &vpcs) != nil || xml.Unmarshal(flowXML, &fl) != nil {
		return nil
	}
	have := map[string]bool{}
	for _, v := range fl.VPCs {
		have[v] = true
	}
	var out []CSPMFinding
	for _, v := range vpcs.Items {
		if v.Default || have[v.ID] {
			continue
		}
		out = append(out, CSPMFinding{Title: fmt.Sprintf("VPC %s (%s) has no flow logs", v.ID, region), Severity: "medium", Category: "logging",
			Resource: v.ID + " " + region, ResourceType: "vpc", MITRE: "T1562.008",
			Description: "Network traffic in this VPC is not recorded, which makes network incidents hard to investigate.",
			Remediation: "Create a VPC flow log to CloudWatch Logs or S3 for all traffic."})
	}
	return out
}

func awsPublicSnapshotFindings(body []byte, region string) []CSPMFinding {
	var r struct {
		IDs []string `xml:"snapshotSet>item>snapshotId"`
	}
	if xml.Unmarshal(body, &r) != nil {
		return nil
	}
	var out []CSPMFinding
	for _, id := range r.IDs {
		out = append(out, CSPMFinding{Title: fmt.Sprintf("EBS snapshot %s is public (%s)", id, region), Severity: "critical", Category: "storage",
			Resource: id + " " + region, ResourceType: "ebs_snapshot", MITRE: "T1530",
			Description: "Anyone with an AWS account can copy this snapshot and read its disk contents.",
			Remediation: "Make the snapshot private (ModifySnapshotAttribute) and enable block public access for EBS snapshots."})
	}
	return out
}

func awsDefaultSGFindings(sgXML []byte, region string) []CSPMFinding {
	var r struct {
		Groups []struct {
			ID      string   `xml:"groupId"`
			Name    string   `xml:"groupName"`
			Ingress []string `xml:"ipPermissions>item>ipProtocol"`
			Egress  []string `xml:"ipPermissionsEgress>item>ipProtocol"`
			VPC     string   `xml:"vpcId"`
		} `xml:"securityGroupInfo>item"`
	}
	if xml.Unmarshal(sgXML, &r) != nil {
		return nil
	}
	var out []CSPMFinding
	for _, g := range r.Groups {
		if g.Name != "default" || len(g.Ingress) == 0 {
			continue
		}
		out = append(out, CSPMFinding{Title: fmt.Sprintf("Default security group %s (%s) has inbound rules", g.ID, region), Severity: "low", Category: "network",
			Resource: g.ID + " " + region, ResourceType: "security_group", MITRE: "T1021",
			Description: "Resources launched without an explicit group inherit the default group; it should allow no traffic.",
			Remediation: "Remove all inbound and outbound rules from the default security group in every VPC."})
	}
	return out
}

func awsKMSRotationFinding(keyID string, rotating bool, region string) *CSPMFinding {
	if rotating {
		return nil
	}
	return &CSPMFinding{Title: fmt.Sprintf("KMS key %s has rotation disabled (%s)", keyID, region), Severity: "low", Category: "encryption",
		Resource: keyID + " " + region, ResourceType: "kms_key", MITRE: "T1552",
		Description: "Customer-managed symmetric key without automatic annual rotation.",
		Remediation: "Enable automatic key rotation."}
}

const awsMaxKMSKeys = 50

func runAWSCSPMRegional(ctx context.Context, creds awsCreds, home bool, add func([]CSPMFinding), skip func(string, string), passed *int) {
	r := creds.Region
	// GuardDuty, Config and Security Hub are checked in every region except
	// Security Hub, which is checked in the home region only.
	gb, gc, err := awsRESTGet(ctx, creds, "guardduty", "guardduty."+r+".amazonaws.com", "/detector")
	switch {
	case err != nil || (gc != 200 && gc != 403):
		skip("guardduty", "detector listing failed in "+r)
	case gc == 403:
		skip("guardduty", "guardduty:ListDetectors denied in "+r)
	default:
		if f := awsGuardDutyFinding(gc, gb, r); f != nil {
			add([]CSPMFinding{*f})
		} else {
			*passed++
		}
	}
	cb, cc, err := awsJSONPost(ctx, creds, "config", "config."+r+".amazonaws.com", "StarlingDoveService.DescribeConfigurationRecorders", "{}")
	if err != nil || cc != 200 {
		skip("config_recorder", "DescribeConfigurationRecorders denied or failed in "+r)
	} else if f := awsConfigRecorderFinding(cc, cb, r); f != nil {
		add([]CSPMFinding{*f})
	} else {
		*passed++
	}
	if home {
		hb, hc, herr := awsRESTGet(ctx, creds, "securityhub", "securityhub."+r+".amazonaws.com", "/accounts")
		if herr != nil {
			skip("security_hub", herr.Error())
		} else if f := awsSecurityHubFinding(hc, hb, r); f != nil {
			add([]CSPMFinding{*f})
		} else if hc == 200 {
			*passed++
		} else {
			skip("security_hub", fmt.Sprintf("DescribeHub returned %d in %s", hc, r))
		}
	}
	// VPC flow logs
	vb, vc, verr := awsQueryCall(ctx, creds, "ec2", "ec2."+r+".amazonaws.com", "Action=DescribeVpcs&Version=2016-11-15")
	fb, fc, ferr := awsQueryCall(ctx, creds, "ec2", "ec2."+r+".amazonaws.com", "Action=DescribeFlowLogs&Version=2016-11-15")
	if verr != nil || ferr != nil || vc != 200 || fc != 200 {
		skip("vpc_flow_logs", "DescribeVpcs/DescribeFlowLogs denied or failed in "+r)
	} else {
		f := awsFlowLogFindings(vb, fb, r)
		add(f)
		if len(f) == 0 {
			*passed++
		}
	}
	// Public EBS snapshots owned by this account.
	sb, sc, serr := awsQueryCall(ctx, creds, "ec2", "ec2."+r+".amazonaws.com",
		"Action=DescribeSnapshots&Version=2016-11-15&Owner.1=self&RestorableBy.1=all&MaxResults=1000")
	if serr != nil || sc != 200 {
		skip("ebs_public_snapshots", "DescribeSnapshots denied or failed in "+r)
	} else {
		f := awsPublicSnapshotFindings(sb, r)
		add(f)
		if len(f) == 0 {
			*passed++
		}
	}
	// KMS rotation for enabled customer-managed symmetric keys.
	kb, kc, kerr := awsJSONPost(ctx, creds, "kms", "kms."+r+".amazonaws.com", "TrentService.ListKeys", `{"Limit":100}`)
	if kerr != nil || kc != 200 {
		skip("kms_rotation", "ListKeys denied or failed in "+r)
		return
	}
	var keys struct {
		Keys []struct {
			KeyID string `json:"KeyId"`
		} `json:"Keys"`
	}
	_ = json.Unmarshal(kb, &keys)
	checked := 0
	for _, k := range keys.Keys {
		if checked >= awsMaxKMSKeys || ctx.Err() != nil {
			skip("kms_rotation", fmt.Sprintf("only %d keys checked in %s", awsMaxKMSKeys, r))
			break
		}
		db, dc, derr := awsJSONPost(ctx, creds, "kms", "kms."+r+".amazonaws.com", "TrentService.DescribeKey", fmt.Sprintf(`{"KeyId":%q}`, k.KeyID))
		if derr != nil || dc != 200 {
			continue
		}
		var d struct {
			KeyMetadata struct {
				Manager string `json:"KeyManager"`
				State   string `json:"KeyState"`
				Spec    string `json:"KeySpec"`
				Origin  string `json:"Origin"`
			} `json:"KeyMetadata"`
		}
		if json.Unmarshal(db, &d) != nil {
			continue
		}
		m := d.KeyMetadata
		if m.Manager != "CUSTOMER" || m.State != "Enabled" || (m.Spec != "" && m.Spec != "SYMMETRIC_DEFAULT") || m.Origin == "EXTERNAL" {
			continue
		}
		rb, rc, rerr := awsJSONPost(ctx, creds, "kms", "kms."+r+".amazonaws.com", "TrentService.GetKeyRotationStatus", fmt.Sprintf(`{"KeyId":%q}`, k.KeyID))
		if rerr != nil || rc != 200 {
			continue
		}
		checked++
		var rot struct {
			Enabled bool `json:"KeyRotationEnabled"`
		}
		_ = json.Unmarshal(rb, &rot)
		if f := awsKMSRotationFinding(k.KeyID, rot.Enabled, r); f != nil {
			add([]CSPMFinding{*f})
		} else {
			*passed++
		}
	}
}

// awsRESTPost issues a signed REST-JSON POST to a path (Security Hub style).
func awsRESTPost(ctx context.Context, creds awsCreds, service, host, path, body string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+host+path, strings.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	awsSign(req, creds, service, []byte(body))
	resp, err := awsClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return b, resp.StatusCode, nil
}
