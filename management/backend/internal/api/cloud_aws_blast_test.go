package api

import (
	"net/url"
	"testing"
)

func TestAWSBlastExposedAdminInstance(t *testing.T) {
	details := []byte(`<R><GetAccountAuthorizationDetailsResult>
<RoleDetailList><member><RoleName>web-role</RoleName><Arn>arn:aws:iam::1:role/web-role</Arn>
<AttachedManagedPolicies><member><PolicyName>AdministratorAccess</PolicyName></member></AttachedManagedPolicies>
<InstanceProfileList><member><Arn>arn:aws:iam::1:instance-profile/web</Arn></member></InstanceProfileList></member>
<member><RoleName>ro</RoleName><Arn>arn:aws:iam::1:role/ro</Arn>
<AttachedManagedPolicies><member><PolicyName>ReadOnlyAccess</PolicyName></member></AttachedManagedPolicies>
<InstanceProfileList><member><Arn>arn:aws:iam::1:instance-profile/ro</Arn></member></InstanceProfileList></member></RoleDetailList>
<UserDetailList><member><UserName>bob</UserName><Arn>x</Arn>
<UserPolicyList><member><PolicyName>p</PolicyName><PolicyDocument>` + url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`) + `</PolicyDocument></member></UserPolicyList></member></UserDetailList>
</GetAccountAuthorizationDetailsResult></R>`)
	roles, users, _ := awsBlastEntities(details)
	if len(roles) != 2 || roles[0].Risk != "critical" || roles[1].Risk != "low" {
		t.Fatalf("roles: %+v", roles)
	}
	if len(users) != 1 || users[0].Risk != "critical" {
		t.Fatalf("users: %+v", users)
	}
	inst := awsBlastInstances([]byte(`<R><reservationSet><item><instancesSet><item><instanceId>i-1</instanceId><instanceState><name>running</name></instanceState><ipAddress>1.2.3.4</ipAddress><iamInstanceProfile><arn>arn:aws:iam::1:instance-profile/web</arn></iamInstanceProfile><groupSet><item><groupId>sg-1</groupId></item></groupSet></item><item><instanceId>i-2</instanceId><instanceState><name>terminated</name></instanceState></item></instancesSet></item></reservationSet></R>`), "us-east-1")
	if len(inst) != 1 {
		t.Fatalf("instances: %+v", inst)
	}
	sgs := awsBlastSGs([]byte(`<R><securityGroupInfo><item><groupId>sg-1</groupId><ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissions></item></securityGroupInfo></R>`), "us-east-1")
	if len(sgs) != 1 || !sgs[0].OpenWorld || !sgs[0].OpenSensitive {
		t.Fatalf("sgs: %+v", sgs)
	}
	res := buildAWSBlast(awsBlastInput{Roles: roles, Users: users, Instances: inst, SGs: sgs}, 1, "1")
	if len(res.HighRiskPaths) != 1 || res.HighRiskPaths[0].Severity != "critical" {
		t.Fatalf("paths: %+v", res.HighRiskPaths)
	}
	if res.Summary.PublicExposures != 1 || res.Summary.PrivEscPaths < 2 {
		t.Fatalf("summary: %+v", res.Summary)
	}
}

func TestAWSBlastPrivateInstanceNoPath(t *testing.T) {
	roles := []awsBlastRole{{Name: "r", Risk: "critical", Profiles: []string{"p"}}}
	res := buildAWSBlast(awsBlastInput{Roles: roles, Instances: []awsBlastInstance{{ID: "i", Region: "r1", ProfileARN: "p", SGs: []string{"sg"}}},
		SGs: []awsBlastSG{{ID: "sg", Region: "r1", OpenWorld: true, OpenSensitive: true}}}, 1, "1")
	if len(res.HighRiskPaths) != 0 || res.Summary.PublicExposures != 0 {
		t.Fatalf("no public IP must mean no exposure: %+v", res)
	}
}

func TestAWSBlastLambdaRoleAndPublicDB(t *testing.T) {
	roles := []awsBlastRole{{Name: "fn-role", ARN: "arn:aws:iam::1:role/fn-role", Risk: "critical"}}
	lambdas := awsBlastLambdas([]byte(`{"Functions":[{"FunctionName":"f","Role":"arn:aws:iam::1:role/fn-role"}]}`), "r1")
	dbs := awsBlastDBs([]byte(`<R><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>db1</DBInstanceIdentifier><Engine>postgres</Engine><PubliclyAccessible>true</PubliclyAccessible><VpcSecurityGroups><VpcSecurityGroupMembership><VpcSecurityGroupId>sg-9</VpcSecurityGroupId></VpcSecurityGroupMembership></VpcSecurityGroups></DBInstance></DBInstances></DescribeDBInstancesResult></R>`), "r1")
	if len(lambdas) != 1 || len(dbs) != 1 || !dbs[0].Public || dbs[0].SGs[0] != "sg-9" {
		t.Fatalf("parse: %+v %+v", lambdas, dbs)
	}
	res := buildAWSBlast(awsBlastInput{Roles: roles, Lambdas: lambdas, DBs: dbs,
		SGs: []awsBlastSG{{ID: "sg-9", Region: "r1", OpenWorld: true, OpenPortsLabel: "5432-5432"}}}, 1, "1")
	if res.Summary.PrivEscPaths != 1 || res.Summary.PublicExposures != 1 || len(res.HighRiskPaths) != 1 || res.HighRiskPaths[0].EndPrivilege != "database_access" {
		t.Fatalf("%+v %+v", res.Summary, res.HighRiskPaths)
	}
	priv := dbs
	priv[0].Public = false
	res = buildAWSBlast(awsBlastInput{DBs: priv, SGs: []awsBlastSG{{ID: "sg-9", Region: "r1", OpenWorld: true}}}, 1, "1")
	if res.Summary.PublicExposures != 0 {
		t.Fatal("non-public DB must not be exposed")
	}
}
