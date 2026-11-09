package api

import (
	"net/url"
	"testing"
)

func trustXML(name, doc string) []byte {
	return []byte(`<R><GetAccountAuthorizationDetailsResult><RoleDetailList><member><RoleName>` + name + `</RoleName><Arn>arn:aws:iam::111111111111:role/` + name +
		`</Arn><AssumeRolePolicyDocument>` + url.QueryEscape(doc) + `</AssumeRolePolicyDocument></member></RoleDetailList></GetAccountAuthorizationDetailsResult></R>`)
}

func TestAWSRoleTrust(t *testing.T) {
	f := awsRoleTrustFindings(trustXML("open", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`))
	if len(f) != 1 || f[0].Severity != "critical" {
		t.Fatalf("wildcard: %+v", f)
	}
	if f = awsRoleTrustFindings(trustXML("cond", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`)); len(f) != 0 {
		t.Fatalf("conditioned wildcard must pass: %+v", f)
	}
	f = awsRoleTrustFindings(trustXML("x", `{"Statement":{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::222222222222:root"]},"Action":"sts:AssumeRole"}}`))
	if len(f) != 1 || f[0].Severity != "medium" {
		t.Fatalf("foreign: %+v", f)
	}
	if f = awsRoleTrustFindings(trustXML("same", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)); len(f) != 0 {
		t.Fatalf("own account and service principals must pass: %+v", f)
	}
}
