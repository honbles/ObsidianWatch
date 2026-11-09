package api

import "testing"

func TestParseAWSOrgAccountsAndMemberCreds(t *testing.T) {
	a, next := parseAWSOrgAccounts([]byte(`{"Accounts":[{"Id":"111111111111","Name":"prod","Email":"p@x","Status":"ACTIVE"},{"Id":"222222222222","Name":"old","Status":"SUSPENDED"}],"NextToken":"t"}`))
	if len(a) != 2 || next != "t" || a[1].Status != "SUSPENDED" {
		t.Fatalf("%+v %q", a, next)
	}
	c := awsMemberCreds(map[string]string{"access_key_id": "K", "secret_access_key": "S", "region": "eu-west-1", "role_arn": "ignored"}, a[0], "ReadRole", "ext")
	if c["role_arn"] != "arn:aws:iam::111111111111:role/ReadRole" || c["account_id"] != "111111111111" || c["external_id"] != "ext" || c["session_token"] != "" {
		t.Fatalf("%v", c)
	}
	if !awsRoleARNRe.MatchString(c["role_arn"]) {
		t.Fatal("derived ARN must pass the assume-role validator")
	}
	if awsRoleNameRe.MatchString("a/b") || awsRoleNameRe.MatchString("") || !awsRoleNameRe.MatchString("OrganizationAccountAccessRole") {
		t.Fatal("role name validation wrong")
	}
}
