package api

import (
	"net/url"
	"testing"
	"time"
)

const awsCredCSV = `user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date
<root_account>,arn:aws:iam::1:root,2020-01-01T00:00:00+00:00,not_supported,2026-10-01T00:00:00+00:00,not_supported,not_supported,false,false,N/A,N/A,false,N/A,N/A
alice,arn:aws:iam::1:user/alice,2020-01-01T00:00:00+00:00,true,2026-11-01T00:00:00+00:00,N/A,N/A,false,true,2025-01-01T00:00:00+00:00,2026-11-01T00:00:00+00:00,false,N/A,N/A
bob,arn:aws:iam::1:user/bob,2020-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2026-10-20T00:00:00+00:00,N/A,false,N/A,N/A
carol,arn:aws:iam::1:user/carol,2020-01-01T00:00:00+00:00,true,2026-11-03T00:00:00+00:00,N/A,N/A,true,false,N/A,N/A,false,N/A,N/A
`

func TestAWSCredReportFindings(t *testing.T) {
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	f, passed := awsCredReportFindings(parseAWSCredentialReport([]byte(awsCredCSV)), now)
	titles := map[string]bool{}
	for _, x := range f {
		titles[x.Title] = true
	}
	for _, want := range []string{
		"IAM user 'alice' has a console password but no MFA",
		"IAM user 'alice' access key 1 is 674 days old",
	} {
		if !titles[want] {
			t.Errorf("missing finding %q; got %v", want, titles)
		}
	}
	for _, x := range f {
		if x.Resource == "carol" || x.Resource == "<root_account>" {
			t.Errorf("unexpected finding for %s: %s", x.Resource, x.Title)
		}
	}
	if passed != 2 { // bob (fresh unused key) and carol are clean
		t.Errorf("passed=%d want 2", passed)
	}
	// bob: key 17 days old and unused -> not flagged yet
	for _, x := range f {
		if x.Resource == "bob" {
			t.Errorf("bob should not be flagged: %s", x.Title)
		}
	}
}

func TestAWSPasswordPolicyExtra(t *testing.T) {
	good := []byte(`<GetAccountPasswordPolicyResponse><GetAccountPasswordPolicyResult><PasswordPolicy><PasswordReusePrevention>24</PasswordReusePrevention><MaxPasswordAge>90</MaxPasswordAge><ExpirePasswords>true</ExpirePasswords></PasswordPolicy></GetAccountPasswordPolicyResult></GetAccountPasswordPolicyResponse>`)
	if got := awsPasswordPolicyExtraFindings(good); len(got) != 0 {
		t.Fatalf("good policy flagged: %v", got)
	}
	weak := []byte(`<GetAccountPasswordPolicyResponse><GetAccountPasswordPolicyResult><PasswordPolicy><MinimumPasswordLength>8</MinimumPasswordLength></PasswordPolicy></GetAccountPasswordPolicyResult></GetAccountPasswordPolicyResponse>`)
	if got := awsPasswordPolicyExtraFindings(weak); len(got) != 2 {
		t.Fatalf("weak policy findings=%d", len(got))
	}
}

func TestAWSAdminPolicyFindings(t *testing.T) {
	admin := url.QueryEscape(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	scoped := url.QueryEscape(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}}`)
	xmlDoc := []byte(`<R><GetAccountAuthorizationDetailsResult><Policies>
	 <member><PolicyName>Everything</PolicyName><AttachmentCount>2</AttachmentCount><PolicyVersionList><member><Document>` + admin + `</Document><IsDefaultVersion>true</IsDefaultVersion></member></PolicyVersionList></member>
	 <member><PolicyName>Reader</PolicyName><AttachmentCount>1</AttachmentCount><PolicyVersionList><member><Document>` + scoped + `</Document><IsDefaultVersion>true</IsDefaultVersion></member></PolicyVersionList></member>
	</Policies></GetAccountAuthorizationDetailsResult></R>`)
	f := awsAdminPolicyFindings(xmlDoc)
	if len(f) != 1 || f[0].Resource != "Everything" || f[0].Severity != "high" {
		t.Fatalf("%+v", f)
	}
	if awsPolicyAllowsAll(`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`) {
		t.Fatal("Deny must not count")
	}
}
