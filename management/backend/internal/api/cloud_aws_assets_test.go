package api

import "testing"

func TestAWSAssetParsers(t *testing.T) {
	inst := awsInstanceAssets([]byte(`<R><reservationSet><item><instancesSet>
	 <item><instanceId>i-1</instanceId><instanceState><name>running</name></instanceState><tagSet><item><key>Name</key><value>web</value></item></tagSet></item>
	 <item><instanceId>i-2</instanceId><instanceState><name>terminated</name></instanceState></item>
	</instancesSet></item></reservationSet></R>`), "eu-west-1")
	if len(inst) != 1 || inst[0].ShortName != "web" || inst[0].State != "RUNNING" || inst[0].Name != "aws:eu-west-1:ec2/Instance/i-1" {
		t.Fatalf("%+v", inst)
	}
	if got := awsSGAssets([]byte(`<R><securityGroupInfo><item><groupId>sg-1</groupId><groupName>web</groupName></item></securityGroupInfo></R>`), "r"); len(got) != 1 || got[0].ShortName != "web" {
		t.Fatalf("%+v", got)
	}
	if got := awsRDSAssets([]byte(`<R><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>db1</DBInstanceIdentifier><DBInstanceStatus>available</DBInstanceStatus></DBInstance></DBInstances></DescribeDBInstancesResult></R>`), "r"); len(got) != 1 || got[0].State != "AVAILABLE" {
		t.Fatalf("%+v", got)
	}
	if got := awsLambdaAssets([]byte(`{"Functions":[{"FunctionName":"f","Runtime":"go1.x"}]}`), "r"); len(got) != 1 || got[0].Labels["runtime"] != "go1.x" {
		t.Fatalf("%+v", got)
	}
	users, next := awsIAMAssets([]byte(`<R><ListUsersResult><Users><member><UserName>a</UserName></member></Users><IsTruncated>true</IsTruncated><Marker>m1</Marker></ListUsersResult></R>`), "user")
	if len(users) != 1 || next != "m1" {
		t.Fatalf("%+v %q", users, next)
	}
	roles, next := awsIAMAssets([]byte(`<R><ListRolesResult><Roles><member><RoleName>r1</RoleName></member></Roles><IsTruncated>false</IsTruncated></ListRolesResult></R>`), "role")
	if len(roles) != 1 || next != "" {
		t.Fatalf("%+v %q", roles, next)
	}
	if b := awsS3Assets([]string{"b1"}); b[0].Location != "global" {
		t.Fatalf("%+v", b)
	}
}
