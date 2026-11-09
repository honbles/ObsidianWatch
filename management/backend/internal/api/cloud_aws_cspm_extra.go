package api

// AW-10 (second slice): RDS exposure/encryption and EBS default-encryption checks.

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
)

func awsRDSFindings(body []byte, region string) []CSPMFinding {
	var r struct {
		DBs []struct {
			ID        string `xml:"DBInstanceIdentifier"`
			Public    string `xml:"PubliclyAccessible"`
			Encrypted string `xml:"StorageEncrypted"`
			Engine    string `xml:"Engine"`
			Backup    int    `xml:"BackupRetentionPeriod"`
		} `xml:"DescribeDBInstancesResult>DBInstances>DBInstance"`
	}
	if xml.Unmarshal(body, &r) != nil {
		return nil
	}
	var out []CSPMFinding
	for _, d := range r.DBs {
		res := fmt.Sprintf("%s (%s) %s", d.ID, d.Engine, region)
		if strings.EqualFold(d.Public, "true") {
			out = append(out, CSPMFinding{Title: "RDS instance is publicly accessible", Severity: "high", Category: "database",
				Description: "RDS instance " + d.ID + " is flagged PubliclyAccessible, so it resolves to a public IP when placed in a public subnet.",
				Resource:    res, ResourceType: "rds_instance", MITRE: "T1190",
				Remediation: "Set PubliclyAccessible=false and reach the database through private networking or a bastion."})
		}
		if strings.EqualFold(d.Encrypted, "false") {
			out = append(out, CSPMFinding{Title: "RDS storage is not encrypted", Severity: "medium", Category: "encryption",
				Description: "RDS instance " + d.ID + " stores data unencrypted at rest.",
				Resource:    res, ResourceType: "rds_instance", MITRE: "T1530",
				Remediation: "Snapshot, copy the snapshot with encryption enabled, and restore to a new instance."})
		}
		if d.Backup == 0 {
			out = append(out, CSPMFinding{Title: "RDS automated backups are disabled", Severity: "low", Category: "resilience",
				Description: "RDS instance " + d.ID + " has a backup retention period of 0 days.",
				Resource:    res, ResourceType: "rds_instance",
				Remediation: "Set BackupRetentionPeriod to at least 7 days."})
		}
	}
	return out
}

func awsEBSDefaultEncryptionFinding(body []byte, region string) *CSPMFinding {
	var r struct {
		On string `xml:"ebsEncryptionByDefault"`
	}
	if xml.Unmarshal(body, &r) != nil || !strings.EqualFold(r.On, "false") {
		return nil
	}
	return &CSPMFinding{Title: "EBS encryption by default is disabled", Severity: "medium", Category: "encryption",
		Description: "New EBS volumes in " + region + " are not encrypted unless requested explicitly.",
		Resource:    "ebs-default-encryption " + region, ResourceType: "account_setting",
		Remediation: "Run ec2:EnableEbsEncryptionByDefault in each region."}
}

func runAWSCSPMExtra(ctx context.Context, creds awsCreds, add func([]CSPMFinding), skip func(string, string), passed *int) {
	rb, rc, err := awsQueryCall(ctx, creds, "rds", "rds."+creds.Region+".amazonaws.com", "Action=DescribeDBInstances&Version=2014-10-31")
	if err != nil || rc != 200 {
		skip("rds", "DescribeDBInstances denied or failed in "+creds.Region)
	} else {
		add(awsRDSFindings(rb, creds.Region))
		*passed++
	}
	eb, ec, err := awsQueryCall(ctx, creds, "ec2", "ec2."+creds.Region+".amazonaws.com", "Action=GetEbsEncryptionByDefault&Version=2016-11-15")
	if err != nil || ec != 200 {
		skip("ebs_default_encryption", "GetEbsEncryptionByDefault denied or failed in "+creds.Region)
	} else {
		if f := awsEBSDefaultEncryptionFinding(eb, creds.Region); f != nil {
			add([]CSPMFinding{*f})
		} else {
			*passed++
		}
	}
}
