package api

import "testing"

func TestAWSGuardDutyConfigHub(t *testing.T) {
	if awsGuardDutyFinding(200, []byte(`{"detectorIds":[]}`), "eu-west-1") == nil {
		t.Fatal("no detector must be flagged")
	}
	if awsGuardDutyFinding(200, []byte(`{"detectorIds":["abc"]}`), "eu-west-1") != nil {
		t.Fatal("existing detector must pass")
	}
	if awsGuardDutyFinding(403, nil, "r") != nil {
		t.Fatal("denied must not produce a finding")
	}
	if awsConfigRecorderFinding(200, []byte(`{"ConfigurationRecorders":[]}`), "r") == nil ||
		awsConfigRecorderFinding(200, []byte(`{"ConfigurationRecorders":[{"name":"default"}]}`), "r") != nil {
		t.Fatal("config recorder logic")
	}
	if awsSecurityHubFinding(403, []byte(`{"__type":"InvalidAccessException"}`), "r") == nil ||
		awsSecurityHubFinding(200, nil, "r") != nil || awsSecurityHubFinding(500, []byte("x"), "r") != nil {
		t.Fatal("security hub logic")
	}
}

func TestAWSFlowSnapshotSGKMS(t *testing.T) {
	vpcs := []byte(`<R><vpcSet><item><vpcId>vpc-1</vpcId><isDefault>false</isDefault></item><item><vpcId>vpc-2</vpcId><isDefault>false</isDefault></item><item><vpcId>vpc-d</vpcId><isDefault>true</isDefault></item></vpcSet></R>`)
	flows := []byte(`<R><flowLogSet><item><resourceId>vpc-2</resourceId></item></flowLogSet></R>`)
	f := awsFlowLogFindings(vpcs, flows, "r")
	if len(f) != 1 || f[0].Resource != "vpc-1 r" {
		t.Fatalf("%+v", f)
	}
	snaps := awsPublicSnapshotFindings([]byte(`<R><snapshotSet><item><snapshotId>snap-1</snapshotId></item></snapshotSet></R>`), "r")
	if len(snaps) != 1 || snaps[0].Severity != "critical" {
		t.Fatalf("%+v", snaps)
	}
	sg := []byte(`<R><securityGroupInfo><item><groupId>sg-1</groupId><groupName>default</groupName><ipPermissions><item><ipProtocol>-1</ipProtocol></item></ipPermissions></item>
	 <item><groupId>sg-2</groupId><groupName>default</groupName></item><item><groupId>sg-3</groupId><groupName>web</groupName><ipPermissions><item><ipProtocol>tcp</ipProtocol></item></ipPermissions></item></securityGroupInfo></R>`)
	d := awsDefaultSGFindings(sg, "r")
	if len(d) != 1 || d[0].Resource != "sg-1 r" {
		t.Fatalf("%+v", d)
	}
	if awsKMSRotationFinding("k", true, "r") != nil || awsKMSRotationFinding("k", false, "r") == nil {
		t.Fatal("kms rotation logic")
	}
}
