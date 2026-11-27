# AWS: capability reference

This page describes, end to end, what ObsidianWatch does with an AWS connector: ingestion, normalisation, posture checks, benchmark and compliance mapping, detections, inventory, blast radius and the console pages. Shared behaviour (scoring, deduplication, UI layout) is in [capability.md](capability.md). Setup is in [configuration-aws.md](configuration-aws.md).

## 1. Log sources and polling

All sources are pulled by the 5-minute connector sync.

| Source | API | Region | Window and cursor | Event type | `agent_id` |
|---|---|---|---|---|---|
| CloudTrail (default) | `LookupEvents` (50 per page, 550 ms between pages: the API allows 2 per second per region, all pages) | Home region, and `us-east-1` for global-service events (IAM, STS, sign-in) when the home region is another; source states `cloudtrail` and `cloudtrail_global` | Per region, from the newest `EventTime` ingested − 2 min (`sync_cursor` is a JSON map of region → time; a plain timestamp from older versions is the home region's). First run: last 24 h. Events come newest first, so a region whose read stops partway (throttling, error, timeout) keeps its previous cursor and is read again; events already stored are skipped by ID. `EventTime` is read as epoch seconds, as the API sends it. | `cloud.cloudtrail` | `aws-cloudtrail-<id>` |
| CloudTrail (S3 mode, `s3_bucket` set) | `ListObjectsV2` + `GetObject` (`.json` / `.json.gz`) | `s3_regions` × `s3_account_ids` | Prefixes for today and the two previous days. A per-prefix "last key" cursor (`start-after`) is kept as JSON in `sync_cursor`. An object that fails 3 times is skipped. | `cloud.cloudtrail` | `aws-cloudtrail-<id>` |
| GuardDuty | `ListDetectors`, `ListFindings` (`findingCriteria.criterion.updatedAt.greaterThanOrEqual` since, sorted by updatedAt, 50 per page, at most 20 pages), `GetFindings` (`findingIds`). GuardDuty's API takes lowerCamelCase members. | Home region | Since `last_sync` − 2 min (first run: 24 h) | `cloud.guardduty` | `aws-guardduty-<id>` |
| Security Hub | `GetFindings` with filter: severity CRITICAL or HIGH, record ACTIVE, workflow NEW or NOTIFIED, product ≠ GuardDuty, UpdatedAt in window. 100 per page, at most 10 pages. | Home region | Since `last_sync` − 2 min | `cloud.securityhub` | `aws-securityhub-<id>` |

GuardDuty and Security Hub are pulled on every sync in both CloudTrail modes. In LookupEvents mode, if the CloudTrail pull fails, the whole sync fails and the GuardDuty and Security Hub pulls are skipped for that run.

*Implemented in:* `cloud_aws.go` (`syncAWS`, `lookupCloudTrailEvents`, `listS3Objects`, `getS3Object`, `pullGuardDuty`), `cloud_aws_securityhub.go`, `cloud_aws_http.go`, `cloud_aws_assume.go`.

## 2. Normalisation

### 2.1 CloudTrail → `cloud.cloudtrail`

| Column | Value |
|---|---|
| `id` | CloudTrail `eventID` |
| `time` | `eventTime` |
| `host` | `awsRegion` (LookupEvents: the region from the embedded record, else `aws`) |
| `user_name` | Both modes: the IAM user name for IAM users, else the identity ARN (an assumed role's session ARN, which baselines and sequence rules fold into the role), else LookupEvents' `Username`. |
| `src_ip` | `sourceIPAddress` |
| `raw` | `event_name`, `event_source`, `event_type`, `aws_region`, `source_ip`, `user_agent`, `error_code`, `error_message`, full `user_identity`, `request_parameters`, `response_elements`, `additional_event_data`, `read_only`, `recipient_account_id`, `resources`, `management_event`, `vpc_endpoint_id`. LookupEvents also stores `username` and the original record string as `_full`. |

**Severity.** The base is 1 (info). For S3 records, an `errorCode` raises it to 3. The following event names set a minimum severity. In S3 mode a failed call to one of them gets one extra level, up to 5. In LookupEvents mode only the table value is used; the error code is not considered.

| Severity | Event names |
|---|---|
| 4 (high) | `DeleteTrail`, `StopLogging`, `DeleteBucket`, `CreateAccessKey`, `PutRolePolicy`, `DeleteSecret`, `DisableKey`, `ScheduleKeyDeletion` |
| 3 (medium) | `PutBucketPolicy`, `PutBucketAcl`, `CreateUser`, `AttachUserPolicy`, `AttachRolePolicy`, `ConsoleLogin`, `PasswordUpdated`, `AuthorizeSecurityGroupIngress`, `DeleteSecurityGroup`, `ModifyInstanceAttribute`, `TerminateInstances`, `CreateRole`, `DeleteRole`, `AssumeRoleWithWebIdentity`, `GetSecretValue` |
| 1 | `RunInstances` |

### 2.2 GuardDuty → `cloud.guardduty`

`id` = finding ID and `time` = `UpdatedAt`, so an updated finding becomes a new row. `host` = instance ID if present, else the region. `src_ip` = remote IPv4 of a network-connection action. `raw` holds the finding type, title, description, numeric severity, region, resource and service blocks.

Severity mapping (GuardDuty 1–10): ≥ 9 → 5, ≥ 7 → 4, ≥ 4 → 3, otherwise 1.

### 2.3 Security Hub → `cloud.securityhub`

`id` = `<finding id>@<UpdatedAt>`, so a re-opened or updated finding creates a new event. `host` = first resource ID, else the region. `raw` holds the product, title, description, `severity_label`, region, account, types and first resource. Severity: CRITICAL → 5, HIGH → 4, otherwise 3.

## 3. Posture checks (CSPM)

A scan runs at startup, every 6 hours, and on **Run Scan**. IAM and S3 checks are global. Regional checks run in every region from `DescribeRegions` (at most 20), four regions in parallel. Each check group that cannot run adds a `not_assessed` entry under the **check key** shown below. The AWS CIS benchmark uses that key to mark controls UNKNOWN.

Finding IDs are `aws-` + hash(account, title, resource). AWS suppression rules are applied inside the scan.

| Check key | Finding title (pattern) | Severity | Category / resource type | What it checks | CIS control |
|---|---|---|---|---|---|
| `iam_account` | Root account has no MFA | critical | iam / iam_root | `AccountMFAEnabled = 0` in `GetAccountSummary` | IAM-02 |
| `iam_account` | Root account has active access keys | high | iam / iam_root | `AccountAccessKeysPresent > 0` | IAM-01 |
| `iam_account` | No IAM account password policy | medium | iam / iam_password_policy | `GetAccountPasswordPolicy` returns 404 | IAM-03 |
| `iam_account` | IAM password policy minimum length is N | low | iam / iam_password_policy | Minimum length 1–13 | IAM-03 |
| `iam_account` | IAM password policy does not prevent reuse of the last 24 passwords | low | iam | `PasswordReusePrevention < 24` | IAM-04 |
| `iam_account` | IAM password policy does not expire passwords within 90 days | low | iam | Expiry off, or max age 0 or > 90 | IAM-05 |
| `iam_credential_report` | IAM user 'X' has a console password but no MFA | high | iam / iam_user | Credential report | IAM-06 |
| `iam_credential_report` | IAM user 'X' has not signed in for N days | low | iam / iam_user | Password last used > 90 days | IAM-08 |
| `iam_credential_report` | IAM user 'X' access key N is D days old | medium | iam / iam_user | Active key last rotated > 90 days | IAM-07 |
| `iam_credential_report` | IAM user 'X' access key N unused for D days | low | iam / iam_user | Active key last used > 45 days | IAM-08 |
| `iam_credential_report` | IAM user 'X' access key N has never been used | low | iam / iam_user | Never used and older than 45 days | IAM-08 |
| `iam_role_trust` | IAM role 'X' can be assumed by any AWS principal | critical | iam / iam_role | Trust `Allow` with principal `*` and no condition | IAM-10 |
| `iam_role_trust` | IAM role 'X' trusts account N without conditions | medium | iam / iam_role | Trust grants another account with no condition | IAM-10 |
| `iam_policies` | Customer-managed policy 'X' allows all actions on all resources | high if attached, else medium | iam / iam_policy | Default version has `Allow` `Action:*` `Resource:*` | IAM-09 |
| `security_groups` | Security group allows all traffic from the internet | critical | network / security_group | Protocol `-1` from `0.0.0.0/0` or `::/0` | NET-01 |
| `security_groups` | Security group exposes port P to the internet | high (22, 3389), medium (other ranges) | network / security_group | From `0.0.0.0/0` or `::/0`. Single ports 80 and 443 are ignored. Other single ports are ignored unless 22 or 3389. | NET-02 |
| `security_groups` | Default security group G (region) has inbound rules | low | network / security_group | Group named `default` with any ingress rule | NET-03 |
| `rds` | RDS instance is publicly accessible | high | database / rds_instance | `PubliclyAccessible = true` | STO-07 |
| `rds` | RDS storage is not encrypted | medium | encryption / rds_instance | `StorageEncrypted = false` | STO-07 |
| `rds` | RDS automated backups are disabled | low | resilience / rds_instance | Backup retention 0 | – |
| `ebs_default_encryption` | EBS encryption by default is disabled | medium | encryption / account_setting | Per region | STO-05 |
| `guardduty` | GuardDuty is not enabled in R | medium | logging / account_setting | No detector in the region | LOG-05 |
| `config_recorder` | AWS Config recorder is not set up in R | low | logging / account_setting | No configuration recorder | LOG-03 |
| `security_hub` | Security Hub is not enabled in R | low | logging / account_setting | Home region only; `InvalidAccessException` | LOG-06 |
| `vpc_flow_logs` | VPC V (R) has no flow logs | medium | logging / vpc | Non-default VPC with no flow log | LOG-04 |
| `ebs_public_snapshots` | EBS snapshot S is public (R) | critical | storage / ebs_snapshot | Owned snapshot restorable by `all` | STO-06 |
| `kms_rotation` | KMS key K has rotation disabled (R) | low | encryption / kms_key | Enabled, customer-managed, symmetric, not external-origin key without rotation. At most 50 keys checked per region. | STO-08 |
| `cloudtrail` | CloudTrail 'T' has log file validation disabled | low | logging / cloudtrail | `DescribeTrails` in the home region | LOG-02 |
| `cloudtrail` | No multi-region CloudTrail trail | high | logging / cloudtrail | No trail with `IsMultiRegionTrail` | LOG-01 |
| `s3_public_access` | S3 bucket 'B' has no Block Public Access configuration | medium | storage / s3_bucket | No bucket-level PAB (404), and account-level Block Public Access (`s3-control` `GetPublicAccessBlock`) does not have all four settings on; when it does, the bucket passes. At most 500 buckets. Buckets whose PAB cannot be read are counted in `not_assessed`. | STO-01 |
| `s3_public_access` | S3 bucket 'B' has Block Public Access partly disabled | medium | storage / s3_bucket | Any of the four flags off | STO-01 |
| `s3_hardening` | S3 bucket 'B' does not have versioning enabled | low | storage / s3_bucket | Status ≠ Enabled. At most 200 buckets. | STO-04 |
| `s3_hardening` | S3 bucket 'B' has no server access logging | low | storage / s3_bucket | No `LoggingEnabled` | LOG-07 |
| `s3_hardening` | S3 bucket 'B' has a bucket policy that allows public access | high | storage / s3_bucket | `Allow` with principal `*` and no condition | STO-02 |
| `s3_hardening` | S3 bucket 'B' policy does not require TLS | low | storage / s3_bucket | No `Deny` on `aws:SecureTransport=false`, or no policy | STO-03 |
| `s3_hardening` | S3 bucket 'B' ACL grants access to everyone | high | storage / s3_bucket | Grant to the `AllUsers` group | STO-02 |

**Per-bucket requests** go to the bucket's own region (`<bucket>.s3.<region>.amazonaws.com`, path-style for names with dots) and are signed for it. The region comes from `GetBucketLocation` on the global endpoint, else the `x-amz-bucket-region` header, and is cached.

**The credential report** is polled 8 times, 1.5 s apart; if it is not ready, `iam_credential_report` is recorded as not assessed with that reason, and the next scan reads it.

**How `passed` is counted.** One pass per check group that ran. For the credential report, one per user with no finding. For S3 PAB and hardening, one per clean bucket. For KMS, one per rotating key. Flow logs, snapshots and EBS count one per region when clean.

*Implemented in:* `cloud_aws_cspm.go`, `cloud_aws_cspm_iam.go`, `cloud_aws_cspm_trust.go`, `cloud_aws_cspm_regional.go`, `cloud_aws_cspm_extra.go`, `cloud_aws_cspm_s3.go`, `cloud_aws_suppress.go`.

## 4. CIS-inspired benchmark

The **CIS Benchmark** tab is titled "CIS AWS-style Foundations Benchmark (subset …)". The 28 controls are evaluated from the latest CSPM result. Nothing new is fetched beyond the CSPM run that **Run Assessment** starts.

- FAIL: at least one open finding whose title matches the control's text pattern. Evidence lists up to 5 resources.
- UNKNOWN: no finding, and one of the control's check keys is in `not_assessed`.
- PASS: otherwise.

| ID | Section | Control | Level | Check keys |
|---|---|---|---|---|
| IAM-01 | IAM | No access keys for the root account | 1 | iam_account |
| IAM-02 | IAM | MFA enabled for the root account | 1 | iam_account |
| IAM-03 | IAM | Password policy requires at least 14 characters | 1 | iam_account |
| IAM-04 | IAM | Password policy prevents reuse of the last 24 passwords | 1 | iam_account |
| IAM-05 | IAM | Passwords expire within 90 days | 1 | iam_account |
| IAM-06 | IAM | MFA enabled for every console user | 1 | iam_credential_report |
| IAM-07 | IAM | Access keys rotated within 90 days | 1 | iam_credential_report |
| IAM-08 | IAM | Unused credentials disabled (45 days) | 1 | iam_credential_report |
| IAM-09 | IAM | No customer-managed policy grants `*:*` | 1 | iam_policies |
| IAM-10 | IAM | No role trust policy is open to any principal or unconstrained other accounts | 1 | iam_role_trust |
| STO-01 | Storage | S3 Block Public Access enabled on every bucket | 1 | s3_public_access |
| STO-02 | Storage | No S3 bucket is public through policy or ACL | 1 | s3_hardening |
| STO-03 | Storage | S3 buckets require TLS | 2 | s3_hardening |
| STO-04 | Storage | S3 versioning enabled | 2 | s3_hardening |
| STO-05 | Storage | EBS encryption by default in every region | 2 | ebs_default_encryption |
| STO-06 | Storage | No public EBS snapshots | 1 | ebs_public_snapshots |
| STO-07 | Storage | RDS instances encrypted and not public | 1 | rds |
| STO-08 | Storage | KMS customer-managed keys rotate | 2 | kms_rotation |
| LOG-01 | Logging | A multi-region CloudTrail trail exists | 1 | cloudtrail |
| LOG-02 | Logging | CloudTrail log file validation enabled | 2 | cloudtrail |
| LOG-03 | Logging | AWS Config recorder enabled in every region | 2 | config_recorder |
| LOG-04 | Logging | VPC flow logs enabled | 2 | vpc_flow_logs |
| LOG-05 | Logging | GuardDuty enabled in every region | 2 | guardduty |
| LOG-06 | Logging | Security Hub enabled | 2 | security_hub |
| LOG-07 | Logging | S3 server access logging enabled | 2 | s3_hardening |
| NET-01 | Network | No security group allows all traffic from the internet | 1 | security_groups |
| NET-02 | Network | No security group exposes admin or wide port ranges to the internet | 1 | security_groups |
| NET-03 | Network | Default security groups allow no traffic | 2 | security_groups |

Score = passed ÷ (passed + failed). Level 1 and Level 2 scores are computed the same way. The result states: "control IDs are our own and the full benchmark is not covered … Not a CIS certification result."

**Matcher caveat:** STO-06 matches any finding title containing "is public". The title "RDS instance is publicly accessible" also contains that text, so a public RDS instance fails STO-06 as well as STO-07.

*Implemented in:* `cloud_aws_cis.go`, `cloud_cis_multi.go` (`tallyCIS`).

## 5. Compliance mapping

The mapping is built from the stored CIS result. Rules: FAIL if every listed control fails, PARTIAL if some fail, NOT_ASSESSED if none fail but some are UNKNOWN, PASS otherwise.

| Framework | Control | Title | Evidence controls |
|---|---|---|---|
| SOC2 | CC6.1 | Logical access and data protection | IAM-01, IAM-02, IAM-06, IAM-09, IAM-10, STO-01, STO-02, STO-05, STO-06, STO-07, STO-08 |
| SOC2 | CC6.2 | Credential lifecycle | IAM-07, IAM-08 |
| SOC2 | CC6.6 | Network boundary protection | NET-01, NET-02, NET-03 |
| SOC2 | CC6.7 | Protection of data in transit | STO-03 |
| SOC2 | CC7.1 | Detection of vulnerabilities and threats | LOG-03, LOG-05, LOG-06 |
| SOC2 | CC7.2 | Monitoring of system activity | LOG-01, LOG-02, LOG-04, LOG-07 |
| SOC2 | A1.2 | Backup and recovery | STO-04 |
| PCI-DSS | 1.3.1 | Inbound traffic restricted | NET-01, NET-02, NET-03 |
| PCI-DSS | 3.5.1 | Stored account data rendered unreadable | STO-05, STO-07, STO-08 |
| PCI-DSS | 4.2.1 | Strong cryptography in transit | STO-03 |
| PCI-DSS | 7.2.1 | Least-privilege access | IAM-01, IAM-09, IAM-10 |
| PCI-DSS | 8.2.6 | Inactive accounts removed or disabled | IAM-08 |
| PCI-DSS | 8.3.6 | Minimum password length | IAM-03 |
| PCI-DSS | 8.3.7 | Password reuse restricted | IAM-04 |
| PCI-DSS | 8.3.9 | Passwords changed periodically | IAM-05 |
| PCI-DSS | 8.4.2 | MFA for access | IAM-02, IAM-06 |
| PCI-DSS | 10.2.1 | Audit logs enabled | LOG-01, LOG-03, LOG-07 |
| PCI-DSS | 10.3.4 | Audit log integrity | LOG-02 |
| PCI-DSS | 11.5.1 | Intrusion detection | LOG-05, LOG-06 |
| ISO27001 | A.5.15 | Access control | IAM-01, IAM-09, IAM-10 |
| ISO27001 | A.5.17 | Authentication information | IAM-03, IAM-04, IAM-05, IAM-07 |
| ISO27001 | A.8.3 | Information access restriction | STO-01, STO-02, STO-06 |
| ISO27001 | A.8.5 | Secure authentication | IAM-02, IAM-06, IAM-08 |
| ISO27001 | A.8.13 | Information backup | STO-04 |
| ISO27001 | A.8.15 | Logging | LOG-01, LOG-02, LOG-03, LOG-07 |
| ISO27001 | A.8.16 | Monitoring activities | LOG-04, LOG-05, LOG-06 |
| ISO27001 | A.8.20 | Network security | NET-01, NET-02, NET-03 |
| ISO27001 | A.8.24 | Use of cryptography | STO-03, STO-05, STO-07, STO-08 |
| NIST-800-53 | AC-2 | Account management | IAM-07, IAM-08 |
| NIST-800-53 | AC-3 | Access enforcement | IAM-09, IAM-10, STO-01, STO-02, STO-06 |
| NIST-800-53 | AC-6 | Least privilege | IAM-01, IAM-09 |
| NIST-800-53 | AU-2 | Event logging | LOG-01, LOG-03, LOG-07 |
| NIST-800-53 | AU-9 | Protection of audit information | LOG-02 |
| NIST-800-53 | CP-9 | System backup | STO-04 |
| NIST-800-53 | IA-2 | Identification and authentication (MFA) | IAM-02, IAM-06 |
| NIST-800-53 | IA-5 | Authenticator management | IAM-03, IAM-04, IAM-05, IAM-07 |
| NIST-800-53 | SC-7 | Boundary protection | NET-01, NET-02, NET-03 |
| NIST-800-53 | SC-8 | Transmission confidentiality | STO-03 |
| NIST-800-53 | SC-28 | Protection of information at rest | STO-05, STO-07, STO-08 |
| NIST-800-53 | SI-4 | System monitoring | LOG-04, LOG-05, LOG-06 |

On the **Compliance** tab, if no CIS result exists, the page says to run the CIS benchmark first. **Remap Compliance** rebuilds the report from the stored CIS result.

*Implemented in:* `cloud_aws_compliance.go`.

## 6. Detections on AWS events

All rules below run on every cloud event (section 3.1 of [capability.md](capability.md)). Most check the CloudTrail `event_name` field (`awsActionHas`). Some search the whole lower-cased raw JSON for keywords. Those are marked "raw text" and can match unintended fields.

Rules with an AWS-specific trigger:

| ID | Name | Sev | MITRE | Triggers on |
|---|---|---|---|---|
| C-AWS-011 | S3 Bucket Replication to External Account | 4 | T1537 | `PutBucketReplication` with a destination bucket ARN |
| C-AWS-012 | S3 Bucket Versioning Disabled | 3 | T1485 | `PutBucketVersioning` with "suspended" |
| C-AWS-013 | S3 Server Access Logging Disabled | 3 | T1562.008 | `PutBucketLogging` without `LoggingEnabled`/`TargetBucket` |
| C-AWS-014 | Large S3 Data Download | 3 | T1530 | `GetObject` with event severity ≥ 3. Needs S3 data events, so it never fires in LookupEvents mode (see section 11). |
| C-AWS-015 | S3 Bucket Encryption Removed | 3 | T1486 | `DeleteBucketEncryption` |
| C-AWS-016 | IAM User Created | 2 | T1136.003 | `CreateUser` without an error code |
| C-AWS-017 | IAM User Added to Admin Group | 4 | T1078.004 | `AddUserToGroup` + raw text admin, administrator or poweruser |
| C-AWS-018 | IAM Password Policy Weakened | 3 | T1556 | `UpdateAccountPasswordPolicy`, `DeleteAccountPasswordPolicy` |
| C-AWS-019 | MFA Device Deregistered | 4 | T1556.006 | `DeactivateMFADevice`, `DeleteVirtualMFADevice` |
| C-AWS-020 | STS AssumeRole Cross-Account | 3 | T1199 | Successful `AssumeRole` into a role of another account than the caller's (when either account cannot be read, it fires) |
| C-AWS-021 | EC2 Instance Created with Public IP | 2 | T1583.003 | `RunInstances` + public IP fields |
| C-AWS-022 | EC2 Snapshot Made Public | 4 | T1530 | `ModifySnapshotAttribute` + raw text "group" or "all" |
| C-AWS-023 | EC2 AMI Made Public | 4 | T1530 | `ModifyImageAttribute` + launchPermission or "all" |
| C-AWS-024 | VPC Flow Logs Disabled | 4 | T1562.008 | `DeleteFlowLogs` |
| C-AWS-025 | EC2 SSH Key Pair Created | 3 | T1098 | `CreateKeyPair`, `ImportKeyPair` |
| C-AWS-026 | Secrets Manager Secret Accessed | 3 | T1552.001 | `GetSecretValue` |
| C-AWS-027 | Secrets Manager Secret Deleted | 4 | T1485 | `DeleteSecret` |
| C-AWS-028 | Parameter Store Sensitive Value Accessed | 3 | T1552.001 | `GetParameter*` with decryption or SecureString |
| C-AWS-029 | GuardDuty Threat Intelligence Feed Match | 4 | T1071 | GuardDuty raw text trojan, backdoor, cryptomining, pentest, scanner |
| C-AWS-030 | GuardDuty Cryptocurrency Mining | 4 | T1496 | GuardDuty raw text cryptomining, bitcoin, monero, coinminer |
| C-AWS-031 | GuardDuty Tor Exit Node Activity | 4 | T1090.003 | GuardDuty raw text "tor". This also matches words such as "storage" and "monitor". |
| C-AWS-032 | GuardDuty Port Scan Detected | 3 | T1046 | GuardDuty raw text portscan or recon:ec2 |
| C-AWS-033 | Lambda Function Policy Made Public | 4 | T1190 | `AddPermission` + lambda + principal `*` |
| C-AWS-034 | Lambda Environment Variables Modified | 3 | T1525 | `UpdateFunctionConfiguration` + environment or variables |
| C-AWS-035 | CloudFormation Stack Deleted | 3 | T1485 | `DeleteStack` |
| C-AWS-036 | AWS Config Recorder Stopped | 4 | T1562.008 | `StopConfigurationRecorder`, `DeleteConfigurationRecorder` |
| C-AWS-037 | Route53 DNS Record Modified | 4 | T1584.002 | `ChangeResourceRecordSets` |
| C-AWS-038 | CloudWatch Alarm Deleted | 3 | T1562.001 | `DeleteAlarms` |
| C-AWS-039 | ECR Image Pushed with Latest Tag | 2 | T1525 | Raw text `InitiateLayerUpload`/`CompleteLayerUpload` + ecr |
| C-AWS-040 | RDS Snapshot Made Public | 5 | T1530 | `ModifyDBSnapshotAttribute` with values to add |
| C-AWS-041 | AWS Console Login Without MFA | 3 | T1078.004 | Successful `ConsoleLogin` with MFAUsed = No |
| C-AWS-042 | AWS Root Account Activity | 5 | T1078.004 | Identity type Root, not ConsoleLogin, not read-only |
| C-AWS-043 | AWS Root Access Key Created | 5 | T1098.001 | `CreateAccessKey` by root |
| C-AWS-044 | AWS Login Profile Created or Changed | 4 | T1098 | `CreateLoginProfile`, `UpdateLoginProfile` |
| C-AWS-045 | AWS AdministratorAccess Policy Attached | 5 | T1098.003 | `Attach{User,Group,Role}Policy` with `policy/AdministratorAccess` |
| C-AWS-046 | AWS SSM SendCommand Executed | 3 | T1651 | `SendCommand`, `StartSession` from ssm.amazonaws.com |
| C-AWS-047 | AWS PassRole Privilege Escalation Pattern | 4 | T1548 | `CreatePolicyVersion` set as default, or `CreateFunction`/`RunInstances`/`CreateStack` mentioning admin or poweruser roles |
| C-AWS-048 | Security Hub Critical Finding | 5 | T1190 | `cloud.securityhub` with label CRITICAL |
| C-AWS-049 | Security Hub High Finding | 4 | T1190 | `cloud.securityhub` with label HIGH |
| C-RECON-001 | AWS Cloud Enumeration – ListBuckets/DescribeInstances Burst | 3 | T1526 | Any single CloudTrail event whose raw text contains ListBuckets, DescribeInstances, ListUsers, ListGroups, ListPolicies, DescribeDBInstances, ListFunctions, GetAccountAuthorizationDetails or ListAttachedUserPolicies. There is no burst threshold. |
| C-RECON-002 | AWS IAM Credential Report Generated | 3 | T1087.004 | `GenerateCredentialReport`, `GetCredentialReport` |
| C-RECON-003 | Cloud Account Metadata Enumeration | 2 | T1526 | Raw text GetAccountSummary, ListAccounts, DescribeOrganization, … (also any provider) |

ObsidianWatch sends `User-Agent: ObsidianWatch-connector/1.0` on every AWS call, and CloudTrail records it. The three recon rules skip events with that user agent, so the connector's own scans do not raise them. A user agent can be copied, so only these low-severity discovery rules use it.
| C-NET-001 | Cloud Security Group Opens SSH/RDP to Internet | 5 | T1190 | `AuthorizeSecurityGroupIngress` + 0.0.0.0/0 or ::/0 + port 22/3389, ssh or rdp |
| C-NET-002 | AWS Security Group Opens All Ports to Internet | 5 | T1562.007 | `AuthorizeSecurityGroupIngress` + world CIDR + all-ports markers |
| C-NET-003 | Cloud VPN Tunnel Deleted | 4 | T1562.007 | `DeleteVpnConnection`, `DeleteCustomerGateway` (and other providers) |
| C-NET-004 | AWS Direct Connect or Transit Gateway Modified | 3 | T1557 | Transit Gateway and Direct Connect create, modify, delete |
| C-NET-005 | Cloud Metadata Service Accessed from Unexpected IP | 5 | T1552.005 | CloudTrail raw text contains 169.254.169.254 or other metadata markers |
| C-LAT-001 | AWS EC2 Instance Connect Used | 3 | T1021.004 | `SendSSHPublicKey` / ec2instanceconnect |
| C-LAT-002 | AWS SSM RunCommand Executed on Multiple Instances | 4 | T1021.006 | SendCommand + RunShellScript or RunPowerShellScript document |
| C-LAT-003 | AWS Role Chaining Detected | 4 | T1548.005 | Successful AssumeRole whose caller is an assumed-role |
| C-ABUSE-001 | Unusual EC2 Instance Type Launched | 3 | T1496 | RunInstances with p2–p4, g4–g5, inf1, trn1 or hpc6a types |
| C-ABUSE-002 | Cloud Compute Quota Increase Requested | 2 | T1496 | `RequestServiceQuotaIncrease` (any provider) |
| C-ABUSE-003 | AWS Spot Instance Fleet or Batch Job Created | 3 | T1496 | Spot fleet, spot data feed, Batch compute environment |

Cross-cloud rules that also match CloudTrail events: C-XCLOUD-002 (critical resource deleted, event severity ≥ 4), C-XCLOUD-003 (StopLogging, DeleteTrail, DeleteConfigurationRecorder, …), C-XCLOUD-004 (`"type":"root"`), C-XCLOUD-005 (ScheduleKeyDeletion, DisableKey), C-XCLOUD-006 (allusers in storage context), C-XCLOUD-007 (CreateUser outside 06:00–22:00 UTC), C-XCLOUD-008 (DeleteDetector, …), C-XCLOUD-009 (AuthorizeSecurityGroup* outside hours), C-XCLOUD-010 (metadata and credential-file strings). C-XCLOUD-001 (unexpected country) is disabled in code (always false).

There are no rules with IDs C-AWS-001 to C-AWS-010. A code comment refers to an older base set of 20 rules that no longer exists.

### 6.1 Sequence correlation (AWS)

| ID | Title | Window | Entity | Sev |
|---|---|---|---|---|
| CORR-SEQ-AWS-001 | AWS console login succeeded after a failed attempt from the same IP | 15 min | Public source IP | 4 |
| CORR-SEQ-AWS-002 | AWS identity created or given a key, then granted permissions | 30 min | Principal | 4 |
| CORR-SEQ-AWS-003 | AWS logging tampered with, then new resources or identities created | 1 h | Principal | 5 |

*Implemented in:* `sequence_correlation.go`.

### 6.2 Behavioural baseline (AWS)

A baseline is kept per principal. Assumed-role session ARNs are folded into `…:role/<name>`. Service principals (`*.amazonaws.com`, AWS service roles) are skipped. Alerts start once the baseline has 20 events.

| ID | Title | Sev | Fires when |
|---|---|---|---|
| ANOM-AWS-001 | [ANOM] AWS Principal Activity from Unknown IP | 3 | Public source IP not in the baseline |
| ANOM-AWS-002 | [ANOM] AWS Principal Using New Service | 2 | Event severity ≥ 3 and the event-source service was never used before |
| ANOM-AWS-004 | [ANOM] AWS Principal Used From Many IPs | 4 | More than 3 distinct public IPs for the principal in the last hour |

Deduplication: one alert per rule, principal and IP or service, per hour. Event type `cloud.aws_anomaly`.

*Implemented in:* `cloud_aws_baseline.go`.

## 7. Asset inventory

This runs **on demand only**, via `POST /api/v1/cloud-connectors/{id}/assets`. The **Full Inventory** button is hidden for AWS connectors, so in practice it is API-only. Stored as `assets:aws:<id>`. The **Asset Graph** tab shows it when present. There are no deletion alerts for AWS.

| Asset type | Source | Scope |
|---|---|---|
| `ec2/Instance`, `ec2/SecurityGroup`, `ec2/Vpc` | EC2 Describe* | Every region (at most 20) |
| `rds/DBInstance`, `lambda/Function` | RDS, Lambda | Every region |
| `s3/Bucket` | `ListBuckets` | Global |
| `iam/User`, `iam/Role` | `ListUsers`, `ListRoles` | Global |

Asset names are `aws:<region|global>:<type>/<id>`. Types that fail are recorded as not assessed.

*Implemented in:* `cloud_aws_assets.go`.

## 8. Blast radius

On demand: **Run Analysis**. The graph is built from:

- `GetAccountAuthorizationDetails` (roles, users, local managed policies)
- `DescribeInstances`, `DescribeSecurityGroups`, `DescribeDBInstances` and Lambda functions in every region (at most 20)
- the stored CSPM result

How it works:

- **Privilege classification.** Attached managed policies are judged by name only: `AdministratorAccess`, `IAMFullAccess` and `PowerUserAccess` are critical; names ending in `*FullAccess` or containing `Admin` are high. Customer-managed and inline documents with `*:*` are also considered. The contents of AWS-managed policies are not fetched.
- **Exposure.** A security group is "open" if it allows the world. It is "sensitive" if one of these ports is exposed: 22, 23, 445, 1433, 3306, 5432, 6379, 9200, 27017, 3389.
- **Paths.** `internet:public → instance → role` when an internet-exposed instance with a public IP runs as a high or critical role. The path is critical if the role is critical and a sensitive port is open, otherwise high. Lambda → role and user → policy edges add privilege-escalation counts. Public RDS instances and CSPM-flagged buckets add public exposures.
- **Summary** shown in the UI: Principals, Attack Paths (`critical_paths`), Priv Esc (`priv_esc_paths`), Public Exp. (`public_exposures`).

*Implemented in:* `cloud_aws_blast.go`.

## 9. What the user sees (AWS specifics)

- **Cloud → Posture**: AWS findings appear under provider "AWS" with the connector label or account ID.
- **Accounts and scans → (AWS connector)**: **Import org accounts** button. **Event Timeline** queries `aws-cloudtrail-<id>`, `aws-guardduty-<id>` and `aws-securityhub-<id>`. The Account ID is filled from AWS by **Test Connection** or on save, so the **Overview** tab shows results. The Compliance Posture mini-bars are labelled with GCP names. The **CIS Benchmark** tab header reads "CIS AWS-style Foundations Benchmark (subset – N controls assessed, not the full benchmark)".
- Connector-form "What will be pulled": CloudTrail (LookupEvents, home region + us-east-1 for IAM/sign-in), IAM activity, GuardDuty and Security Hub findings. S3 mode is not mentioned (API-only fields).

## 10. Limits

| Item | Limit |
|---|---|
| CSPM regions | 20 (first 20 from DescribeRegions) |
| S3 buckets: PAB check / hardening | 500 / 200 |
| KMS keys checked per region | 50 |
| IAM policy and role pages | 5 × 100 policies, 10 × 100 roles |
| GuardDuty findings per sync | 20 pages × 50 |
| Security Hub findings per sync | 10 pages × 100 |
| Org import | 200 accounts |
| Manual CSPM timeout | 3 minutes |
| AWS HTTP client | 4 attempts with exponential backoff for 429, 5xx and throttling errors; 2-minute request timeout |

## 11. Known gaps

- LookupEvents returns management events only. Data events (S3 `GetObject`, ECR layer uploads) need S3 mode with a trail that records them. C-AWS-014 depends on this.
- C-AWS-014 can never match. `GetObject` is not in the severity table, so its severity is 1 unless an error code raises it (S3 mode). Errored events are then blocked by the outcome gate.
- GuardDuty and Security Hub use `last_sync` − 2 min as their window. `last_sync` also advances on failed syncs, so a failure longer than one interval can skip findings in that gap.
- GuardDuty and Security Hub are read in the home region only.
