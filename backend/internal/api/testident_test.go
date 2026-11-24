package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"obsidianwatch/backend/pkg/agentid"
)

// asClaimedAgent gives a unit-test request the certificate identity of the
// agent it claims to be (body agent_id, else ?agent_id), as the identity
// gate would after verifying a real certificate. Handler unit tests are about
// what the handler does with a batch, not about authentication.
func asClaimedAgent(r *http.Request) *http.Request {
	id := r.URL.Query().Get("agent_id")
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		var v struct {
			AgentID string `json:"agent_id"`
		}
		if json.Unmarshal(b, &v) == nil && v.AgentID != "" {
			id = v.AgentID
		}
	}
	return withIdentity(r, agentid.Identity{AgentID: id, Serial: "test"})
}
