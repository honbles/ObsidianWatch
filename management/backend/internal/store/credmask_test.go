package store

import "testing"

func TestMaskCreds(t *testing.T) {
	in := map[string]string{
		"access_key_id": "AKIA123", "secret_access_key": "s", "session_token": "t",
		"client_id": "c", "client_secret": "x", "tenant_id": "t1", "service_account": "{json}",
		"token": "ghp_x", "pat": "p", "webhook_secret": "w", "s3_bucket": "b", "s3_bucket_path": "p/",
		"base_url": "https://gitlab.example", "empty_token": "", "project_id": "p", "api_key": "k",
	}
	out := maskCreds(in)
	for _, k := range []string{"secret_access_key", "session_token", "client_secret", "service_account", "token", "pat", "webhook_secret", "api_key"} {
		if out[k] != maskedSecret {
			t.Errorf("%s must be masked, got %q", k, out[k])
		}
	}
	for _, k := range []string{"access_key_id", "client_id", "tenant_id", "s3_bucket", "s3_bucket_path", "base_url", "project_id"} {
		if out[k] != in[k] {
			t.Errorf("%s must stay visible, got %q", k, out[k])
		}
	}
	if _, ok := out["empty_token"]; ok {
		t.Error("empty secret should be omitted, not shown as set")
	}
	if in["token"] != "ghp_x" {
		t.Error("input map must not be modified")
	}
}
