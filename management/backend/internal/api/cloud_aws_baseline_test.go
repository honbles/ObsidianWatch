package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func awsTestEvent(user, ip, src string, sev int) store.Event {
	return store.Event{UserName: &user, SrcIP: &ip, Severity: sev, Raw: []byte(`{"event_source":"` + src + `"}`)}
}

func TestAWSPrincipalFoldsSessions(t *testing.T) {
	a := awsPrincipal(awsTestEvent("arn:aws:sts::1:assumed-role/Deploy/sess-1", "", "", 1))
	b := awsPrincipal(awsTestEvent("arn:aws:sts::1:assumed-role/Deploy/sess-2", "", "", 1))
	if a != b || a != "arn:aws:sts::1:role/Deploy" {
		t.Fatalf("got %q %q", a, b)
	}
	if awsPrincipal(awsTestEvent("ec2.amazonaws.com", "", "", 1)) != "" || awsPrincipal(awsTestEvent("", "", "", 1)) != "" {
		t.Fatal("service/empty principals must be skipped")
	}
}

func TestAWSAnomalies(t *testing.T) {
	b := &principalBaseline{EventCount: 50, KnownIPs: map[string]ipRecord{"8.8.8.8": {}}, KnownMethods: map[string]int{"s3": 40}}
	if got := awsAnomalies(b, awsTestEvent("u", "8.8.8.8", "s3.amazonaws.com", 3), 1); len(got) != 0 {
		t.Fatalf("normal: %v", got)
	}
	got := awsAnomalies(b, awsTestEvent("u", "1.2.3.4", "iam.amazonaws.com", 3), 5)
	want := map[string]bool{"ANOM-AWS-001": true, "ANOM-AWS-002": true, "ANOM-AWS-004": true}
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected %s", g)
		}
	}
	if awsAnomalies(b, awsTestEvent("u", "10.0.0.5", "iam.amazonaws.com", 1), 1) != nil {
		t.Fatal("private IP and low severity must not alert")
	}
	young := &principalBaseline{EventCount: 5, KnownIPs: map[string]ipRecord{}, KnownMethods: map[string]int{}}
	if awsAnomalies(young, awsTestEvent("u", "1.2.3.4", "iam.amazonaws.com", 4), 9) != nil {
		t.Fatal("immature baseline must stay quiet")
	}
}
