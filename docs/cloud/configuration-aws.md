# AWS connector: configuration

This page covers how to create AWS credentials for ObsidianWatch, what each connector field does, and how to check and troubleshoot the connection. See [deployment.md](deployment.md) for the shared setup and [capability-aws.md](capability-aws.md) for what is collected.

*Implemented in:* `internal/api/cloud_aws.go`, `cloud_aws_assume.go`, `cloud_aws_org.go`, `cloud_aws_cspm*.go`, `cloud_aws_assets.go`, `cloud_aws_blast.go`, `cloud_aws_securityhub.go`; UI `pages/cloud/shared.jsx` (`PROVIDERS.aws`), `pages/cloud/connectors.jsx`.

## 1. Credential model

ObsidianWatch signs every request itself with AWS Signature V4. It does not use the AWS SDK. It needs a **base identity**, which is an access key ID and secret access key. A session token is optional. Two modes are supported:

| Mode | How | When to use |
|---|---|---|
| Direct key | The IAM user's policies grant the read permissions | Quick tests |
| Assume role (recommended) | The IAM user may only call `sts:AssumeRole` on a read-only role. The connector assumes that role (`RoleSessionName=obsidianwatch`, 1 hour) for every call. The temporary credentials are cached until 5 minutes before they expire. | Production, cross-account, AWS Organizations |

If **External ID** is set, it is sent as `ExternalId` in AssumeRole. AssumeRole always goes to the global endpoint `https://sts.amazonaws.com/`, signed for `us-east-1`.

## 2. Required permissions

Attach the AWS-managed **`SecurityAudit`** policy to the role (or user) that the connector uses. It covers the CSPM, CIS, inventory and blast-radius reads. Also allow the following, because `SecurityAudit` does not cover all data reads:

| Permission | Used for |
|---|---|
| `cloudtrail:LookupEvents` | CloudTrail ingestion (default mode) |
| `s3:ListBucket`, `s3:GetObject` on the trail bucket | CloudTrail S3 mode only |
| `guardduty:ListDetectors`, `guardduty:ListFindings`, `guardduty:GetFindings` | GuardDuty ingestion and the GuardDuty-enabled check |
| `securityhub:GetFindings`, `securityhub:DescribeHub` | Security Hub ingestion and the enabled check |
| `sts:GetCallerIdentity` | **Test Connection** (always allowed by AWS) |
| `organizations:ListAccounts` | **Import org accounts** only, on the management or delegated-admin account |

API calls made by posture, inventory and blast radius. `SecurityAudit` should cover these; confirm with your own policy simulator:

- IAM: `GetAccountSummary`, `GetAccountPasswordPolicy`, `GenerateCredentialReport`, `GetCredentialReport`, `GetAccountAuthorizationDetails` (also `ListUsers`/`ListRoles` style calls for inventory)
- EC2: `DescribeRegions`, `DescribeSecurityGroups`, `DescribeInstances`, `DescribeVpcs`, `DescribeFlowLogs`, `DescribeSnapshots`, `GetEbsEncryptionByDefault`
- RDS `DescribeDBInstances`; Lambda list functions; KMS `ListKeys`, `DescribeKey`, `GetKeyRotationStatus`; Config `DescribeConfigurationRecorders`; CloudTrail `DescribeTrails`
- S3: `ListAllMyBuckets` and, per bucket, `GetBucketPublicAccessBlock`, `GetBucketVersioning`, `GetBucketLogging`, `GetBucketPolicy`, `GetBucketAcl`

### Example: read-only role with an external ID

Trust policy on the role in the monitored account. Replace the principal with the IAM user that ObsidianWatch uses:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::111111111111:user/obsidianwatch" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<long random string>" } }
  }]
}
```

Permissions on the role: the `SecurityAudit` managed policy plus an inline policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "cloudtrail:LookupEvents",
      "guardduty:ListDetectors", "guardduty:ListFindings", "guardduty:GetFindings",
      "securityhub:GetFindings", "securityhub:DescribeHub"
    ],
    "Resource": "*"
  }]
}
```

The IAM user itself needs only `sts:AssumeRole` on that role ARN.

## 3. Connector fields

Fields shown in the **Amazon Web Services** form:

| Field (UI label) | Key | Required | Effect |
|---|---|---|---|
| Access Key ID | `access_key_id` | Yes | Base identity. Stored in plain text (it is an identifier). |
| Secret Access Key | `secret_access_key` | Yes | Encrypted at rest. Masked in the UI. |
| Region | `region` | No (default `us-east-1`) | The **home region**. Used for CloudTrail LookupEvents, GuardDuty and Security Hub ingestion, `DescribeRegions`, and the Security Hub-enabled check. Validated against `^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`. |
| Role ARN to assume (optional, recommended) | `role_arn` | No | If set, every call uses AssumeRole credentials. Must match `arn:aws…:iam::<12 digits>:role/<name>`. |
| External ID (optional) | `external_id` | No | Sent with AssumeRole. Encrypted at rest, but shown in clear text in the connector list (its name ends in `_id`). |
| Account ID (filled by Test Connection) | `account_id` | Filled automatically | The connector key, CSPM scope label, S3 prefix default, finding IDs and alert scope. **Test Connection** fills it from `GetCallerIdentity` (the assumed role's account when a role is set). Saving with it empty reads it the same way; if that call fails, the save is refused with the reason. |

Fields accepted by the API but **not shown in the form**. To use them, set them with `POST /api/v1/cloud-connectors` using the same provider and account ID. That updates the stored credentials, and you must re-send every field.

| Key | Effect |
|---|---|
| `session_token` | Temporary base credentials. They expire, and are not refreshed. |
| `s3_bucket` | Switches CloudTrail collection from LookupEvents to **S3 mode**. Validated as a bucket name. |
| `s3_bucket_region` | Region of the trail bucket (default: `region`). |
| `s3_account_ids` | Comma list of account IDs whose log prefixes to read (default: `account_id`). |
| `s3_regions` | Comma list of regions to read (default: `region`). |
| `s3_org_id` | AWS Organizations ID (`o-…`) for organization-trail layout `AWSLogs/<org>/<acct>/CloudTrail/<region>/<date>/`. |

### Regions and scope

| Feature | Regions covered |
|---|---|
| CloudTrail LookupEvents | The home region, plus `us-east-1` when the home region is another one: AWS records the events of global services (IAM, STS, console sign-in, Organizations) only in `us-east-1`. Each region has its own cursor; `us-east-1` reports as source `cloudtrail_global`. |
| CloudTrail S3 mode | Every `s3_accounts × s3_regions` combination, for today and the two previous days |
| GuardDuty, Security Hub ingestion | Home region only (Security Hub's aggregation region if you use cross-region aggregation) |
| CSPM regional checks, inventory, blast radius | Every region returned by `DescribeRegions`, at most **20**. Falls back to the home region if `DescribeRegions` is denied. |
| IAM, S3 | Global |

### AWS Organizations

On a connector that holds management-account (or delegated-admin) credentials, click **Import org accounts** in the connector header. You will be asked for:

1. **Role name** present in every member account (for example `ObsidianWatchReadOnly`). It must match `^[\w+=,.@-]{1,64}$`.
2. **External ID** (optional).

A dry run lists the accounts first. After you confirm, one AWS connector is created for each `ACTIVE` member account, up to 200 (`organizations:ListAccounts`, 20 per page, at most 10 pages). Each connector copies the base access key, secret, region and session token. It sets `account_id` to the member account and `role_arn` to `arn:aws:iam::<acct>:role/<role name>`, and is labelled with the account name. S3 settings are not copied. The member role's trust policy must allow the management connector's base identity. Accounts that match the current connector's account ID are skipped.

## 4. Verification

1. Click **Test Connection**. On success: "Connection successful!". Behind the scenes, AssumeRole (if configured) and `GetCallerIdentity` ran.
2. Save, then click **Sync now**. After a few seconds the sidebar dot should be green (`connected`).
3. Open the **Event Timeline** tab. CloudTrail events appear with event type `cloud.cloudtrail`. On first run the window is the last 24 hours. LookupEvents data typically lags 5–15 minutes.
4. On the **Overview** tab, click **Run Scan**. Expand "N checks failed – show" to see checks that could not run.
5. On the **CIS Benchmark** tab, click **Run Assessment**. Then on **Compliance**, click **Remap Compliance**.
6. Optional: `GET /api/v1/cloud-connectors/{id}/sources` shows `cloudtrail`, `cloudtrail_s3`, `guardduty`, `securityhub` states.

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Test fails "STS GetCallerIdentity returned 403 (InvalidClientTokenId: …)" | Wrong or deactivated key | Check the key. The AWS error code and message are shown. |
| "AssumeRole denied (HTTP 403, AccessDenied: …)" | Trust policy, External ID, or the base user lacks `sts:AssumeRole` on the role | Fix the trust policy principal and condition, and the user's policy |
| "role_arn is not a valid IAM role ARN" / "invalid AWS region" / "invalid s3_bucket name" | Input validation | Correct the value |
| Status `error`, last error contains `cloudtrail API 400 … AccessDenied` | Missing `cloudtrail:LookupEvents` | Add the permission |
| Status `connected` but no GuardDuty events | No detector in the home region. Recorded as `not_enabled`. A 403 on list detectors is also treated as "not enabled". | Enable GuardDuty, or check the permission |
| No Security Hub events | Hub not enabled (`not_enabled`) or no new or notified HIGH/CRITICAL findings | Expected behaviour; see capability page |
| Scan result shows `not_assessed` for `iam_credential_report`, `s3_hardening`, … | Missing SecurityAudit-level permission. The reason text names the API. | Attach `SecurityAudit` |
| `s3_public_access` not assessed: "Block Public Access of N bucket(s) could not be read" | Missing `s3:GetBucketPublicAccessBlock` or `s3:GetBucketLocation` | Attach `SecurityAudit` |
| Manual **Run Scan** fails with a context timeout on large accounts | Manual AWS scans have a 3-minute limit. The scheduled scan allows 30 minutes. | Wait for the 6-hour scheduled scan, or reduce scope |
| Signature errors in the log | Server clock skew beyond what the retry logic can learn | Sync the server clock (NTP) |

## 6. End-to-end verification on a test account

`tools/aws-verify.sh` provisions everything needed to check the connector against a real AWS account, generates the activity the detections must alert on, asks ObsidianWatch what it saw, and removes everything again. Run it in **AWS CloudShell** (the `>_` icon in the console), signed in as an administrator of a test account:

```
bash aws-verify.sh up          # connector user + read-only role, a trail, deliberately weak but unexposed settings
bash aws-verify.sh attack      # CloudTrail activity: IAM, security groups, secrets, S3, logging tampering, recon
bash aws-verify.sh check       # PASS / NOT YET per expected finding and alert (15 minutes after attack)
bash aws-verify.sh down        # delete everything, restore the password policy
```

With `OW_URL` and `OW_USER`/`OW_PASS` (or `OW_TOKEN`) set, `up` also creates the connector in ObsidianWatch and starts a sync and a scan, and `check` reads the sources, the scan result and the alerts through the API; without them `up` prints the connector values to paste and `check` prints the checklist. `OW_INSECURE=1` accepts a self-signed certificate. Options for `up`: `--guardduty` (GuardDuty with sample findings, 30-day trial), `--ebs` (a public snapshot of an empty 1 GB volume), `--kms` (a key without rotation), `--no-trail`.

Everything is named `ow-verify-*` and tagged `owner=obsidianwatch-verify`; nothing it creates is reachable or holds data (security groups attached to nothing, an empty bucket, a user with a console password but no permissions, an open-trust role with a deny-all policy). The default run costs nothing or a few cents. `up` weakens the account password policy until `down` restores it, so use a test account. The console sign-in without MFA (C-AWS-041) and root activity (C-AWS-042) cannot be scripted: `attack` prints how to trigger the first by hand.
