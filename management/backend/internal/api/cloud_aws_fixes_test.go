package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

// fakeAWS records every request's host and signing scope and answers like AWS.
type fakeAWS struct {
	mu    sync.Mutex
	calls []string // "host|path?query|region/service"
	fail  map[string]int
}

func (f *fakeAWS) scope(r *http.Request) string {
	a := r.Header.Get("Authorization")
	i := strings.Index(a, "Credential=")
	if i < 0 {
		return ""
	}
	parts := strings.Split(strings.SplitN(a[i+11:], ",", 2)[0], "/")
	if len(parts) < 4 {
		return ""
	}
	return parts[2] + "/" + parts[3]
}

func (f *fakeAWS) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sc := f.scope(r)
		f.mu.Lock()
		f.calls = append(f.calls, r.Host+"|"+r.URL.RequestURI()+"|"+sc)
		f.mu.Unlock()
		host := r.Host
		switch {
		case host == "sts.amazonaws.com":
			if sc != "us-east-1/sts" {
				w.WriteHeader(403)
				fmt.Fprint(w, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>Credential should be scoped to a valid region.</Message></Error></ErrorResponse>`)
				return
			}
			fmt.Fprint(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/ow</Arn><UserId>X</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case host == "s3.amazonaws.com" && r.URL.Path == "/eu-bucket" && r.URL.RawQuery == "location":
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">eu-west-1</LocationConstraint>`)
		case host == "s3.amazonaws.com" && r.URL.Path == "/us-bucket" && r.URL.RawQuery == "location":
			fmt.Fprint(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`)
		case host == "eu-bucket.s3.eu-west-1.amazonaws.com" && sc == "eu-west-1/s3":
			if r.URL.RawQuery == "versioning" {
				fmt.Fprint(w, `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
				return
			}
			fmt.Fprint(w, `<ok/>`)
		case host == "us-bucket.s3.us-east-1.amazonaws.com" && sc == "us-east-1/s3":
			fmt.Fprint(w, `<ok/>`)
		case strings.HasPrefix(host, "guardduty."):
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			switch {
			case r.URL.Path == "/detector":
				fmt.Fprint(w, `{"detectorIds":["d1"]}`)
			case r.URL.Path == "/detector/d1/findings":
				if _, ok := body["findingCriteria"]; !ok || body["maxResults"] == nil {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"message":"unknown members"}`)
					return
				}
				fmt.Fprint(w, `{"findingIds":["f1"]}`)
			case r.URL.Path == "/detector/d1/findings/get":
				if _, ok := body["findingIds"]; !ok {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"message":"findingIds is required"}`)
					return
				}
				fmt.Fprint(w, `{"findings":[{"accountId":"123456789012","region":"eu-west-1","id":"f1","type":"Recon:EC2/PortProbeUnprotectedPort","title":"t","severity":5.0,"createdAt":"2026-11-27T10:00:00.000Z","updatedAt":"2026-11-27T10:05:00.000Z","resource":{"resourceType":"Instance","instanceDetails":{"instanceId":"i-1"}}}]}`)
			default:
				w.WriteHeader(404)
			}
		case strings.HasPrefix(host, "cloudtrail."):
			region := strings.TrimSuffix(strings.TrimPrefix(host, "cloudtrail."), ".amazonaws.com")
			if sc != region+"/cloudtrail" {
				w.WriteHeader(400)
				return
			}
			f.mu.Lock()
			n := f.fail[region]
			f.mu.Unlock()
			var req struct{ NextToken string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			now := time.Now().UTC()
			if req.NextToken == "" { // newest page first
				ev := map[string]interface{}{"EventId": region + "-new", "EventName": "CreateUser", "EventTime": now.Add(-1 * time.Minute).Unix(), "Username": "sess",
					"CloudTrailEvent": `{"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::123456789012:assumed-role/Admin/sess"},"awsRegion":"` + region + `"}`}
				json.NewEncoder(w).Encode(map[string]interface{}{"Events": []interface{}{ev}, "NextToken": "p2"})
				return
			}
			if n > 0 { // the older page fails
				w.WriteHeader(400)
				fmt.Fprint(w, `{"__type":"AccessDeniedException","message":"nope"}`)
				return
			}
			ev := map[string]interface{}{"EventId": region + "-old", "EventName": "ListUsers", "EventTime": now.Add(-30 * time.Minute).Unix(), "Username": "ow",
				"CloudTrailEvent": `{"userIdentity":{"type":"IAMUser","userName":"ow","arn":"arn:aws:iam::123456789012:user/ow"}}`}
			json.NewEncoder(w).Encode(map[string]interface{}{"Events": []interface{}{ev}})
		default:
			w.WriteHeader(400)
			fmt.Fprint(w, `<Error><Code>Unexpected</Code><Message>`+host+`</Message></Error>`)
		}
	}
}

func withFakeAWS(t *testing.T) *fakeAWS {
	f := &fakeAWS{fail: map[string]int{}}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	old := awsClient
	awsClient = &http.Client{Transport: hostRewrite{u}}
	t.Cleanup(func() { awsClient = old })
	return f
}

func TestAWSTestConnectionSignsGlobalSTSForUSEast1(t *testing.T) {
	withFakeAWS(t)
	acct, err := testAWSConnection(context.Background(), awsCreds{AccessKeyID: "AKIA", SecretAccessKey: "s", Region: "eu-west-1"})
	if err != nil || acct != "123456789012" {
		t.Fatalf("home region eu-west-1 must still pass: %v %q", err, acct)
	}
}

func TestAWSBucketRegionEndpoints(t *testing.T) {
	f := withFakeAWS(t)
	awsBucketRegions = sync.Map{}
	creds := awsCreds{AccessKeyID: "AKIA", SecretAccessKey: "s", Region: "us-east-1"}
	b, c, err := awsBucketGet(context.Background(), creds, "eu-bucket", "?versioning")
	if err != nil || c != 200 || !strings.Contains(string(b), "Enabled") {
		t.Fatalf("eu bucket: %v %d %s\n%v", err, c, b, f.calls)
	}
	if _, c, err := awsBucketGet(context.Background(), creds, "us-bucket", "?acl"); err != nil || c != 200 {
		t.Fatalf("us bucket: %v %d %v", err, c, f.calls)
	}
	// Cached: a second call does not ask for the location again.
	n := len(f.calls)
	_, _, _ = awsBucketGet(context.Background(), creds, "eu-bucket", "?logging")
	if len(f.calls) != n+1 {
		t.Fatalf("location must be cached: %v", f.calls[n:])
	}
}

func TestAWSLookupBothRegionsAndCursorOnFailure(t *testing.T) {
	f := withFakeAWS(t)
	conn := &store.CloudConnector{ID: 7, Credentials: map[string]string{"access_key_id": "AKIA", "secret_access_key": "s", "region": "eu-west-1"}}
	old := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	conn.SyncCursor = old.Format(time.RFC3339Nano) // pre-upgrade plain cursor = home region
	f.fail["us-east-1"] = 1
	_, cur, err := syncAWS(context.Background(), conn, nil, nil, discardLogger())
	if err == nil {
		t.Fatal("the us-east-1 failure must be reported")
	}
	got := awsLookupCursors(cur, "eu-west-1")
	if !got["eu-west-1"].After(old) {
		t.Fatalf("home region read fully: cursor must advance: %v", got)
	}
	if _, ok := got["us-east-1"]; ok {
		t.Fatalf("us-east-1 stopped partway: its cursor must not advance past unread pages: %v", got)
	}
	hosts := map[string]bool{}
	for _, c := range f.calls {
		hosts[strings.SplitN(c, "|", 2)[0]] = true
	}
	if !hosts["cloudtrail.eu-west-1.amazonaws.com"] || !hosts["cloudtrail.us-east-1.amazonaws.com"] {
		t.Fatalf("both regions read: %v", hosts)
	}
	if r := awsLookupRegions("us-east-1"); len(r) != 1 {
		t.Fatalf("us-east-1 home reads one region: %v", r)
	}
}

func TestLookupEventUserAndURIEncode(t *testing.T) {
	inner := map[string]interface{}{"userIdentity": map[string]interface{}{"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/Admin/s1"}}
	if u := lookupEventUser(lookupEvent{Username: "s1"}, inner); u != "arn:aws:sts::1:assumed-role/Admin/s1" {
		t.Fatal(u)
	}
	inner = map[string]interface{}{"userIdentity": map[string]interface{}{"type": "IAMUser", "userName": "bob", "arn": "arn:aws:iam::1:user/bob"}}
	if u := lookupEventUser(lookupEvent{Username: "bob"}, inner); u != "bob" {
		t.Fatal(u)
	}
	if u := lookupEventUser(lookupEvent{Username: "x"}, nil); u != "x" {
		t.Fatal(u)
	}
	if e := awsURIEncode("a b+c/~*"); e != "a%20b%2Bc%2F~%2A" {
		t.Fatal(e)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestGuardDutyRequestMembersAreCamelCase(t *testing.T) {
	withFakeAWS(t)
	f, err := listGuardDutyFindings(context.Background(), awsCreds{AccessKeyID: "A", SecretAccessKey: "s", Region: "eu-west-1"}, "d1", time.Now().Add(-time.Hour))
	if err != nil || len(f) != 1 || f[0].Resource.InstanceDetails.InstanceID != "i-1" || f[0].UpdatedAt.IsZero() {
		t.Fatalf("%v %+v", err, f)
	}
}

func TestLookupEventsEpochSeconds(t *testing.T) {
	var r struct{ Events []lookupEvent }
	body := `{"Events":[{"EventId":"e1","EventName":"CreateUser","EventTime":1.7646852055E9,"Username":"ow","CloudTrailEvent":"{}"},
		{"EventId":"e2","EventTime":"2026-11-27T10:00:00Z"}]}`
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	if r.Events[0].EventTime.Unix() != 1764685205 || r.Events[0].EventName != "CreateUser" || r.Events[1].EventTime.Hour() != 10 {
		t.Fatalf("%+v", r.Events)
	}
}

func TestReconRulesSkipOwnConnector(t *testing.T) {
	mk := func(ua string) store.Event {
		raw, _ := json.Marshal(map[string]interface{}{"event_name": "ListBuckets", "user_agent": ua})
		return store.Event{EventType: "cloud.cloudtrail", Raw: raw}
	}
	var r001 ThreatSig
	for _, s := range cloudReconSignatures {
		if s.ID == "C-RECON-001" {
			r001 = s
		}
	}
	if r001.Match(mk(awsUserAgent + " (go)")) {
		t.Fatal("the connector's own ListBuckets must not raise C-RECON-001")
	}
	if !r001.Match(mk("aws-cli/2.15 Python/3.11")) {
		t.Fatal("someone else's ListBuckets must")
	}
}

func TestAssumeRoleCrossAccountOnly(t *testing.T) {
	mk := func(caller, role string) store.Event {
		raw, _ := json.Marshal(map[string]interface{}{"event_name": "AssumeRole", "user_identity": map[string]string{"accountId": caller},
			"request_parameters": map[string]string{"roleArn": "arn:aws:iam::" + role + ":role/R"}})
		return store.Event{EventType: "cloud.cloudtrail", Raw: raw}
	}
	if awsAssumeRoleCrossAccount(mk("111111111111", "111111111111")) || !awsAssumeRoleCrossAccount(mk("111111111111", "222222222222")) {
		t.Fatal("cross-account only")
	}
}
