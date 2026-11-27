package api

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

// TestAWSVerifyScriptExpectations replays, as LookupEvents returns them, the
// CloudTrail records that tools/aws-verify.sh "attack" produces, through the
// real converter and every rule set, and checks each expected rule fires (and
// that ObsidianWatch's own scan calls do not raise the recon rules).
func TestAWSVerifyScriptExpectations(t *testing.T) {
	admin := `{"type":"IAMUser","principalId":"AIDAX","arn":"arn:aws:iam::123456789012:user/admin","accountId":"123456789012","accessKeyId":"ASIAX","userName":"admin"}`
	connector := `{"type":"AssumedRole","arn":"arn:aws:sts::123456789012:assumed-role/ow-verify-readonly/obsidianwatch","accountId":"123456789012","sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::123456789012:role/ow-verify-readonly"}}}`
	cli := "aws-cli/2.22.0 md/awscrt#0.23 ua/2.0 os/linux#6.1 md/arch#x86_64 lang/python#3.12 exec-env/CloudShell"
	type rec struct {
		name, source, params, ua, who string
		want                          []string // rule IDs that must fire
		not                           []string // rule IDs that must not
	}
	cases := []rec{
		{"StopLogging", "cloudtrail", `{"name":"arn:aws:cloudtrail:eu-west-1:123456789012:trail/ow-verify-trail"}`, cli, admin, []string{"C-XCLOUD-003"}, nil},
		{"CreateUser", "iam", `{"userName":"ow-verify-temp-101010","tags":[{"key":"owner","value":"obsidianwatch-verify"}]}`, cli, admin, []string{"C-AWS-016"}, nil},
		{"AttachUserPolicy", "iam", `{"userName":"ow-verify-temp-101010","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}`, cli, admin, []string{"C-AWS-045"}, nil},
		{"CreateLoginProfile", "iam", `{"userName":"ow-verify-nomfa","passwordResetRequired":false}`, cli, admin, []string{"C-AWS-044"}, nil},
		{"UpdateLoginProfile", "iam", `{"userName":"ow-verify-nomfa","passwordResetRequired":false}`, cli, admin, []string{"C-AWS-044"}, nil},
		{"UpdateAccountPasswordPolicy", "iam", `{"minimumPasswordLength":8,"requireSymbols":false,"requireNumbers":false,"requireUppercaseCharacters":false,"requireLowercaseCharacters":false,"allowUsersToChangePassword":true}`, cli, admin, []string{"C-AWS-018"}, nil},
		{"AuthorizeSecurityGroupIngress", "ec2", `{"groupId":"sg-0a1","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"groups":{},"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]},"ipv6Ranges":{},"prefixListIds":{}}]}}`, cli, admin, []string{"C-NET-001"}, nil},
		{"AuthorizeSecurityGroupIngress", "ec2", `{"groupId":"sg-0a1","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":3389,"toPort":3389,"groups":{},"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]},"ipv6Ranges":{},"prefixListIds":{}}]}}`, cli, admin, []string{"C-NET-001"}, nil},
		{"AuthorizeSecurityGroupIngress", "ec2", `{"groupId":"sg-0a2","ipPermissions":{"items":[{"ipProtocol":"-1","groups":{},"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]},"ipv6Ranges":{},"prefixListIds":{}}]}}`, cli, admin, []string{"C-NET-002"}, nil},
		{"CreateKeyPair", "ec2", `{"keyName":"ow-verify-key-101010","keyType":"rsa","keyFormat":"pem"}`, cli, admin, []string{"C-AWS-025"}, nil},
		{"GetSecretValue", "secretsmanager", `{"secretId":"ow-verify-secret-101010"}`, cli, admin, []string{"C-AWS-026"}, nil},
		{"DeleteSecret", "secretsmanager", `{"secretId":"ow-verify-secret-101010","forceDeleteWithoutRecovery":true}`, cli, admin, []string{"C-AWS-027"}, nil},
		{"GetParameter", "ssm", `{"name":"/ow-verify/param-101010","withDecryption":true}`, cli, admin, []string{"C-AWS-028"}, nil},
		{"PutBucketVersioning", "s3", `{"bucketName":"ow-verify-weak","Host":"ow-verify-weak.s3.eu-west-1.amazonaws.com","versioning":"","VersioningConfiguration":{"Status":"Suspended","xmlns":"http://s3.amazonaws.com/doc/2006-03-01/"}}`, "[" + cli + "]", admin, []string{"C-AWS-012"}, nil},
		{"DeleteBucketEncryption", "s3", `{"bucketName":"ow-verify-weak","Host":"ow-verify-weak.s3.eu-west-1.amazonaws.com","encryption":""}`, "[" + cli + "]", admin, []string{"C-AWS-015"}, nil},
		{"ListBuckets", "s3", `{"Host":"s3.eu-west-1.amazonaws.com"}`, "[" + cli + "]", admin, []string{"C-RECON-001"}, nil},
		{"GenerateCredentialReport", "iam", `null`, cli, admin, []string{"C-RECON-002"}, nil},
		// ObsidianWatch's own scans: silent.
		{"ListBuckets", "s3", `{"Host":"s3.amazonaws.com"}`, "[" + awsUserAgent + "]", connector, nil, []string{"C-RECON-001"}},
		{"GenerateCredentialReport", "iam", `null`, awsUserAgent, connector, nil, []string{"C-RECON-002"}},
		{"GetAccountSummary", "iam", `null`, awsUserAgent, connector, nil, []string{"C-RECON-003"}},
		{"AssumeRole", "sts", `{"roleArn":"arn:aws:iam::123456789012:role/ow-verify-readonly","roleSessionName":"obsidianwatch","externalId":"x","durationSeconds":3600}`, awsUserAgent,
			`{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/ow-verify-connector","accountId":"123456789012","userName":"ow-verify-connector"}`, nil, []string{"C-AWS-020"}},
	}
	sets := everySigSets()
	for i, c := range cases {
		inner, _ := json.Marshal(map[string]interface{}{
			"eventVersion": "1.10", "userIdentity": json.RawMessage(c.who), "eventTime": "2026-11-27T19:00:00Z",
			"eventSource": c.source + ".amazonaws.com", "eventName": c.name, "awsRegion": "eu-west-1",
			"sourceIPAddress": "3.250.1.2", "userAgent": c.ua, "requestParameters": json.RawMessage(c.params),
			"responseElements": nil, "eventType": "AwsApiCall", "managementEvent": true, "recipientAccountId": "123456789012",
		})
		// As LookupEvents sends it: EventTime in epoch seconds.
		page := `{"Events":[{"EventId":"e` + string(rune('a'+i)) + `","EventName":"` + c.name + `","EventTime":1.7646852E9,"EventSource":"` + c.source +
			`.amazonaws.com","Username":"admin","CloudTrailEvent":` + jsonQuoteT(string(inner)) + `}]}`
		var resp struct{ Events []lookupEvent }
		if err := json.Unmarshal([]byte(page), &resp); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		ce := lookupEventToCloudEvent(resp.Events[0], 1)
		ev := store.Event{EventType: ce.EventType, Raw: ce.Raw, Severity: ce.Severity, Time: time.Now(), Host: ce.Host}
		hit := map[string]bool{}
		for _, set := range sets {
			for _, sig := range set {
				if sig.Match(ev) && awsErrorAllows(sig, ev) {
					hit[sig.ID] = true
				}
			}
		}
		var got []string
		for id := range hit {
			got = append(got, id)
		}
		sort.Strings(got)
		for _, w := range c.want {
			if !hit[w] {
				t.Errorf("%s (%s): %s did not fire; fired: %s", c.name, c.ua[:12], w, strings.Join(got, ","))
			}
		}
		for _, n := range c.not {
			if hit[n] {
				t.Errorf("%s by ObsidianWatch: %s must not fire; fired: %s", c.name, n, strings.Join(got, ","))
			}
		}
	}
}

func jsonQuoteT(s string) string { b, _ := json.Marshal(s); return string(b) }
