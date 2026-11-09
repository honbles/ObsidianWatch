package api

// G-19: keyless GCP authentication via Workload Identity Federation.
//
// Besides service-account keys, a connector may be given an "external_account"
// credential configuration (the JSON produced by `gcloud iam workload-identity-pools
// create-cred-config`). The subject token is read from a file under
// /var/run/secrets/ (e.g. a Kubernetes projected service-account token), exchanged at
// Google STS, and optionally used to impersonate a service account. Arbitrary
// file paths, URL credential sources and non-Google endpoints are rejected so a
// pasted credential cannot read local files or be pointed at another host.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
)

type gcpExternalAccount struct {
	Audience         string `json:"audience"`
	SubjectTokenType string `json:"subject_token_type"`
	TokenURL         string `json:"token_url"`
	ImpersonationURL string `json:"service_account_impersonation_url"`
	CredentialSource struct {
		File   string `json:"file"`
		Format struct {
			Type      string `json:"type"`
			FieldName string `json:"subject_token_field_name"`
		} `json:"format"`
	} `json:"credential_source"`
}

const wifSecretsDir = "/var/run/secrets/"

func validateWIFConfig(c gcpExternalAccount) error {
	u, err := neturl.Parse(c.TokenURL)
	if err != nil || u.Scheme != "https" || u.Hostname() != "sts.googleapis.com" {
		return fmt.Errorf("external_account token_url must be https://sts.googleapis.com/…")
	}
	if c.Audience == "" || !strings.HasPrefix(c.Audience, "//iam.googleapis.com/") {
		return fmt.Errorf("external_account audience must start with //iam.googleapis.com/")
	}
	if c.ImpersonationURL != "" {
		iu, err := neturl.Parse(c.ImpersonationURL)
		if err != nil || iu.Scheme != "https" || iu.Hostname() != "iamcredentials.googleapis.com" {
			return fmt.Errorf("service_account_impersonation_url must be https://iamcredentials.googleapis.com/…")
		}
	}
	f := filepath.Clean(c.CredentialSource.File)
	if c.CredentialSource.File == "" || !strings.HasPrefix(f, wifSecretsDir) {
		return fmt.Errorf("credential_source.file must be a path under %s (URL and arbitrary file sources are not supported)", wifSecretsDir)
	}
	return nil
}

func readWIFSubjectToken(c gcpExternalAccount) (string, error) {
	b, err := os.ReadFile(filepath.Clean(c.CredentialSource.File))
	if err != nil {
		return "", fmt.Errorf("read subject token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if c.CredentialSource.Format.Type == "json" {
		var m map[string]interface{}
		if json.Unmarshal(b, &m) != nil {
			return "", fmt.Errorf("subject token file is not valid JSON")
		}
		tok, _ = m[c.CredentialSource.Format.FieldName].(string)
	}
	if tok == "" {
		return "", fmt.Errorf("subject token is empty")
	}
	return tok, nil
}

func wifPostJSON(ctx context.Context, url, bearer string, form neturl.Values, jsonBody interface{}, out interface{}) error {
	var req *http.Request
	var err error
	if form != nil {
		req, err = http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(form.Encode()))
		if req != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		b, _ := json.Marshal(jsonBody)
		req, err = http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(b)))
		if req != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode) // body can contain account details
	}
	return json.Unmarshal(body, out)
}

// gcpExternalAccountToken exchanges the workload's subject token for an access token.
func gcpExternalAccountToken(ctx context.Context, c gcpExternalAccount, scope string) (string, error) {
	if err := validateWIFConfig(c); err != nil {
		return "", err
	}
	subject, err := readWIFSubjectToken(c)
	if err != nil {
		return "", err
	}
	stsScope := scope
	if c.ImpersonationURL != "" {
		stsScope = "https://www.googleapis.com/auth/cloud-platform"
	}
	var sts struct {
		AccessToken string `json:"access_token"`
	}
	if err := wifPostJSON(ctx, c.TokenURL, "", neturl.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {c.Audience},
		"scope":                {stsScope},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token_type":   {c.SubjectTokenType},
		"subject_token":        {subject},
	}, nil, &sts); err != nil {
		return "", fmt.Errorf("STS exchange failed: %w", err)
	}
	if sts.AccessToken == "" {
		return "", fmt.Errorf("STS returned no access token")
	}
	if c.ImpersonationURL == "" {
		return sts.AccessToken, nil
	}
	var imp struct {
		AccessToken string `json:"accessToken"`
	}
	if err := wifPostJSON(ctx, c.ImpersonationURL, sts.AccessToken, nil,
		map[string]interface{}{"scope": []string{scope}}, &imp); err != nil {
		return "", fmt.Errorf("service account impersonation failed: %w", err)
	}
	if imp.AccessToken == "" {
		return "", fmt.Errorf("impersonation returned no access token")
	}
	return imp.AccessToken, nil
}
