package api

import (
	"encoding/json"
	"testing"
)

func TestAzureTokenExpiresInStringOrNumber(t *testing.T) {
	for _, in := range []string{`{"access_token":"a","expires_in":"3599"}`, `{"access_token":"a","expires_in":3599}`} {
		var tk azureToken
		if err := json.Unmarshal([]byte(in), &tk); err != nil || int(tk.ExpiresIn) != 3599 {
			t.Fatalf("%s -> %v %d", in, err, tk.ExpiresIn)
		}
	}
}
