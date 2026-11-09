package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"obsidianwatch/management/internal/store"
)

// alertEntityKey (D-06) fingerprints the specific activity behind an alert
// — process name + command line — so that dedup keys which previously
// only covered host+hour+rule don't collapse genuinely different attacker
// activity into one alert just because it happened to match the same rule
// on the same host within the same hour. Two unrelated processes tripping
// the same Sigma rule on one host now produce two alerts, not one.
func alertEntityKey(ev store.Event) string {
	proc := strOrDash(ev.ProcessName)
	cmd := strOrDash(ev.CommandLine)
	if isCloudEvent(ev) {
		// AW-05 / G-13: cloud events carry no process context, and their
		// Host is only a region/zone/project, so every principal in a
		// region collapsed into one alert per hour (and two connectors in
		// the same region collided). Entity = connector + principal + source IP.
		sum := sha256.Sum256([]byte(strings.ToLower(ev.AgentID) + "\x00" +
			strings.ToLower(strOrDash(ev.UserName)) + "\x00" + strOrDash(ev.SrcIP) + "\x00" + cloudResourceID(ev)))
		return hex.EncodeToString(sum[:])[:12]
	}
	if proc == "-" && cmd == "-" {
		// No process context (e.g. network/DNS events) — fall back to
		// whatever identifies the activity for this event type.
		proc = strOrDash(ev.DstIP)
		cmd = strOrDash(ev.FilePath)
	}
	sum := sha256.Sum256([]byte(strings.ToLower(proc) + "\x00" + strings.ToLower(cmd)))
	return hex.EncodeToString(sum[:])[:12]
}

// cloudResourceID (CC-01) extracts the acted-on resource from a cloud event's
// raw JSON so one principal touching different resources yields distinct
// alerts. Returns "-" when the provider record carries none.
func cloudResourceID(ev store.Event) string {
	if len(ev.Raw) == 0 {
		return "-"
	}
	var r struct {
		ResourceID   string          `json:"resource_id"`        // Azure activity
		ResourceName string          `json:"resource_name"`      // GCP GKE / audit
		Resource     json.RawMessage `json:"resource"`           // string for entra/devops; object for GCP (ignored)
		Repo         string          `json:"repo"`               // devops
		Resources    json.RawMessage `json:"resources"`          // AWS CloudTrail: [{"ARN":...}]
		ReqParams    json.RawMessage `json:"request_parameters"` // AWS CloudTrail
	}
	if json.Unmarshal(ev.Raw, &r) != nil {
		return "-"
	}
	var resStr string
	_ = json.Unmarshal(r.Resource, &resStr) // only used when it is a plain string
	for _, v := range []string{r.ResourceID, r.ResourceName, r.Repo, resStr} {
		if v != "" {
			return strings.ToLower(v)
		}
	}
	if v := awsResourceID(r.Resources, r.ReqParams); v != "" {
		return strings.ToLower(v)
	}
	return "-"
}

// awsResourceID picks the acted-on resource from a CloudTrail record: the first
// listed resource ARN, else the first identifying request parameter.
func awsResourceID(resources, reqParams json.RawMessage) string {
	var list []struct {
		ARN  string `json:"ARN"`
		Name string `json:"resourceName"`
	}
	if json.Unmarshal(resources, &list) == nil {
		for _, x := range list {
			if x.ARN != "" {
				return x.ARN
			}
			if x.Name != "" {
				return x.Name
			}
		}
	}
	var p map[string]interface{}
	if json.Unmarshal(reqParams, &p) == nil {
		for _, k := range []string{"bucketName", "instanceId", "functionName", "roleName", "userName", "groupName", "keyId", "trailName", "name"} {
			if v, ok := p[k].(string); ok && v != "" {
				return k + ":" + v
			}
		}
	}
	return ""
}
