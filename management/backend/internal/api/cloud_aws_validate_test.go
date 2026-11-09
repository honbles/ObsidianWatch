package api

import "testing"

func TestAWSHostValidators(t *testing.T) {
	for _, r := range []string{"us-east-1", "eu-west-2", "ap-southeast-1", "us-gov-west-1"} {
		if !awsRegionRe.MatchString(r) {
			t.Errorf("region %q should pass", r)
		}
	}
	for _, r := range []string{"169.254.169.254#", "evil.com/", "us-east-1.evil.com#", "", "us east 1"} {
		if awsRegionRe.MatchString(r) {
			t.Errorf("region %q should fail", r)
		}
	}
	for _, b := range []string{"my-trail-bucket", "a.b.c-logs"} {
		if !awsBucketRe.MatchString(b) {
			t.Errorf("bucket %q should pass", b)
		}
	}
	for _, b := range []string{"x#", "a/b", "UPPER", "evil.com@x", "a"} {
		if awsBucketRe.MatchString(b) {
			t.Errorf("bucket %q should fail", b)
		}
	}
}
