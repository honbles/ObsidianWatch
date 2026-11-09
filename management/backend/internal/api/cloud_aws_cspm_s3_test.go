package api

import "testing"

func TestAWSBucketPolicyFacts(t *testing.T) {
	pub, tls := awsBucketPolicyFacts(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)
	if !pub || tls {
		t.Fatalf("pub=%v tls=%v", pub, tls)
	}
	pub, tls = awsBucketPolicyFacts(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}},
	 {"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`)
	if pub || !tls {
		t.Fatalf("conditioned allow must not be public; pub=%v tls=%v", pub, tls)
	}
}

func TestAWSBucketFindings(t *testing.T) {
	f, ok := awsS3BucketFindings("b1", awsS3Probe{
		versioningOK: true, versioningXML: []byte(`<VersioningConfiguration></VersioningConfiguration>`),
		loggingOK: true, loggingXML: []byte(`<BucketLoggingStatus></BucketLoggingStatus>`),
		policyOK: true, policy: `{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}}`,
		aclOK: true, aclXML: []byte(`<Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>`),
	})
	if !ok || len(f) != 5 { // versioning, logging, public policy, no-TLS, public ACL
		t.Fatalf("ok=%v findings=%d", ok, len(f))
	}
	clean, ok := awsS3BucketFindings("b2", awsS3Probe{
		versioningOK: true, versioningXML: []byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`),
		loggingOK: true, loggingXML: []byte(`<BucketLoggingStatus><LoggingEnabled></LoggingEnabled></BucketLoggingStatus>`),
		policyOK: true, policy: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
		aclOK: true, aclXML: []byte(`<AccessControlPolicy></AccessControlPolicy>`),
	})
	if !ok || len(clean) != 0 {
		t.Fatalf("clean bucket flagged: %v", clean)
	}
	if _, ok := awsS3BucketFindings("b3", awsS3Probe{}); ok {
		t.Fatal("a bucket where nothing could be read must be reported as unassessed")
	}
}
