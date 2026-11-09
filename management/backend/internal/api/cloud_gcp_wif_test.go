package api

import (
	"encoding/json"
	"testing"
)

func TestValidateWIFConfig(t *testing.T) {
	good := `{"type":"external_account","audience":"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x",
	"subject_token_type":"urn:ietf:params:oauth:token-type:jwt","token_url":"https://sts.googleapis.com/v1/token",
	"service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a@p.iam.gserviceaccount.com:generateAccessToken",
	"credential_source":{"file":"/var/run/secrets/tokens/gcp"}}`
	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(good), &sa); err != nil || sa.Type != "external_account" {
		t.Fatalf("unmarshal: %v %+v", err, sa)
	}
	if err := validateWIFConfig(sa.gcpExternalAccount); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
	bad := map[string]func(c *gcpExternalAccount){
		"token_url":   func(c *gcpExternalAccount) { c.TokenURL = "https://evil.example/token" },
		"file":        func(c *gcpExternalAccount) { c.CredentialSource.File = "/etc/passwd" },
		"traversal":   func(c *gcpExternalAccount) { c.CredentialSource.File = "/var/run/secrets/../../etc/shadow" },
		"impersonate": func(c *gcpExternalAccount) { c.ImpersonationURL = "https://evil.example/x" },
		"audience":    func(c *gcpExternalAccount) { c.Audience = "https://evil.example" },
	}
	for name, mut := range bad {
		c := sa.gcpExternalAccount
		mut(&c)
		if validateWIFConfig(c) == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}
