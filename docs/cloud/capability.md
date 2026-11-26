# Cloud security: cross-provider capability overview

This page describes what all three providers share: the data flow, event model, detection pipeline, posture scoring, compliance mapping, alerting and the console pages. Provider details are in [capability-aws.md](capability-aws.md), [capability-azure.md](capability-azure.md) and [capability-gcp.md](capability-gcp.md). For setup, see [deployment.md](deployment.md).

## 1. Data flow

```
provider API ──(5 min sync)──> CloudEvent ──> events table (event_type "cloud.*", os = aws|azure|gcp)
                                               │
                     ┌─────────────────────────┼───────────────────────────────┐
                     v                         v                               v
       DetectionEngine (signatures)   Correlation engines (GCP, Azure)   Baselines (AWS, Azure, GCP)
                     │                         │                               │
                     └──────────────> alerts table (deduplicated) <────────────┘

provider API ──(6 h CSPM / on demand)──> CSPMResult ──> settings "cspm:<p>:<id>" ──> cloud_scan_history
                                              ├──> CIS result  "cis:<p>:<id>"
                                              ├──> compliance  "compliance:<p>:<id>"
                                              └──> new-critical alerts (scheduled runs only)
on demand: inventory "assets:<p>:<id>", blast radius "blast:<p>:<id>"
```

*Implemented in:* `internal/api/cloud_engine.go`, `detection_engine.go`, `cloud_gcp_correlation.go`, `cloud_azure_correlation.go`, `cloud_*_baseline.go`, `cspm_newcritical.go`, `internal/store/scan_history.go`.

## 2. Event normalisation

Every ingested record becomes one row in `events` with these common columns:

| Column | Content |
|---|---|
| `id` | Provider record ID (CloudTrail eventID, GCP insertId, Entra ID, …). Some are made unique with a timestamp suffix or hash (see provider pages). `(id, time)` is the conflict key, so re-reading a record is a no-op. |
| `time` | Provider event time |
| `agent_id` | `<provider>-<source>-<connector id>`, for example `aws-cloudtrail-7`, `gcp-auditlog-3`, `azure-entra-5`. The **Event Timeline** tab queries by these IDs. |
| `host` | Provider-specific entity: AWS region or instance, Azure `<sub prefix>/<resource group>` or user UPN, GCP project or zone |
| `os` | `aws`, `azure` or `gcp` |
| `event_type` | `cloud.<source>` (list per provider page) |
| `severity` | 1 info, 3 medium, 4 high, 5 critical. 2 (low) is used only by some sources. Severity is computed per source. |
| `source` | Source name, for example `cloudtrail`, `gcp_audit_log` |
| `user_name`, `src_ip`, `dst_ip`, `dst_port`, `proto` | Principal and network fields where available |
| `raw` | JSON with the normalised fields plus the important parts of the original record. Capped at 256 KiB. |

## 3. Detections on cloud events

### 3.1 Signature engine

The detection engine pages through new events by `ingested_at`. The cursor persists, so late-arriving cloud logs are still evaluated. It runs every `OW_DETECTION_INTERVAL_SECONDS` seconds (default 10, range 2–300). Any event whose `event_type` starts with `cloud.` gets the cloud rule sets **instead of** endpoint rules:

| Applied to | Rule sets |
|---|---|
| Every cloud event | `cloudSignaturesExtended` (C-AWS-011…049, C-AZ-006…030, C-GCP-006…020, C-XCLOUD-*), `cloudReconSignatures` (C-RECON-*), `cloudNetworkSignatures` (C-NET-*), `cloudLateralSignatures` (C-LAT-*), `cloudComputeAbuseSignatures` (C-ABUSE-*), `awsExtraSignatures` (C-AWS-041…047) |
| GCP events (and provider `cloud`) | GCP IAM, credential, compute, data, network, defense-evasion, persistence, SCC, new, policy, escalation and telemetry sets |
| Azure events (and provider `cloud`) | Azure IAM, Entra identity, compute, data, network, defense-evasion, Defender, resource-log and audit sets |

The provider comes from `os`. If `os` is not one of the three, it is guessed from the event type. Most rules check `event_type` themselves, so a rule for another provider does not match.

Gates applied before a match counts:

- **Retired rules** `C-GCP-075` and `C-GCP-082` are skipped (duplicates of C-GCP-046 and C-GCP-072).
- **Per-rule state**: rules disabled on the **Rules** page are skipped, and severity overrides are applied.
- **Signature suppression rules** are created on the Rules page (stored as `suppress:gcp:*`). Despite the name, they are evaluated for **every** cloud event. A rule matches on signature ID (exact or prefix), principal (exact or suffix), source-IP prefix, method substring, UTC hour window and expiry.
- **Outcome gates**: an AWS CloudTrail event with an `errorCode`, or an Azure Activity event with status `Failed`, triggers only rules whose name contains fail, denied, brute, unauthor (AWS also recon, enumerat). A denied attempt therefore does not alert as if it had succeeded.
- **Rule contract hook** (`engineGate`): allowlist, observe-only and enable states shared with the rest of the platform.

The alert title is `[<MITRE>] <rule name>`. The description contains the rule description, MITRE, category, host, OS and user.

### 3.2 Alert deduplication

1. **Event key.** Signature alerts use `EventID = sig:<rule>:host:<host>:h:<yyyymmddhh>`, so one rule raises at most one alert per host per hour.
2. **Store-level merge** (`CreateAlertDeduped`). If an open or acknowledged alert with the same title and host (or agent ID) was seen in the last **30 minutes**, and was created less than **24 hours** ago, that alert is updated instead (`occurrence_count + 1`, `last_seen = now`, severity raised to the maximum). Concurrent inserts are serialised with an advisory lock.

Correlation, anomaly, asset and CSPM alerts use their own event keys (see section 6 and the provider pages). They go through the same store-level merge.

### 3.3 Correlation and baselines

| Engine | Providers | Cadence | Input window |
|---|---|---|---|
| GCP correlation (`CORR-GCP-*`) | GCP | every 30 s | Cursor over `ingested_at` |
| Azure correlation (`CORR-AZ-*`) | Azure | every 30 s | Events with `time` in the last **2 minutes** (5 at startup) |
| Sequence correlator (`CORR-SEQ-AWS-*`) | AWS | with the detection engine | Detection cursor |
| GCP baseline (`ANOM-GCP-*`) | GCP | learn every 15 min, detect every 2 min | Cursor |
| Azure baseline (`ANOM-AZ-*`) | Azure | learn every 15 min, detect every 2 min | Events with `time` in the last 2 minutes |
| AWS baseline (`ANOM-AWS-*`) | AWS | learn every 15 min (30 days at startup), detect every 2 min | Cursor |

Baselines are stored as settings (`baseline:<provider>:<principal>`). They learn only from events at least 1 hour old with severity ≤ 3, and fire only after a principal has at least 20 learned events.

## 4. Posture (CSPM)

### 4.1 Finding model

Every provider produces the same `CSPMFinding`:

| Field | Meaning |
|---|---|
| `id` | Stable hash: `aws-`/`az-`/`gcp-` + 12 hex characters of SHA-256(scope, title, resource). SCC findings use the SCC finding name. |
| `title`, `description`, `remediation` | Plain-language text. The title usually embeds the resource name. |
| `severity` | `critical`, `high`, `medium`, `low` or `info` |
| `category` | `iam`, `network`, `storage`, `compute`, `logging`, `sql`, `kms`, plus AWS `database`, `encryption`, `resilience` |
| `resource`, `resource_type` | Affected resource and its type |
| `mitre` | ATT&CK technique where set |
| `status` | `open` or `suppressed` |
| `scanned_at` | Scan start time |

The result also contains counts (`critical`, `high`, `medium`, `low`, `total_findings`, `passed`), `errors` (checks that failed), `not_assessed` (checks skipped, with a reason) and `scan_duration`.

**`passed` is not a per-control count.** Each check function adds a number of passes that depends on the provider. Sometimes it is one per resource with no finding, sometimes one per region or per check group. The pass rate below is therefore an approximation.

### 4.2 Risk score and pass rate (computed in the browser)

`riskScore` in `pages/cloud/shared.jsx`:

```
raw   = 10·critical + 5·high + 2·medium + 0.5·low
total = total_findings + passed
score = min(100, round(raw / total × 10))      (0 when total = 0)
```

| Score | Label |
|---|---|
| ≥ 80 | Critical Risk |
| ≥ 60 | High Risk |
| ≥ 40 | Medium Risk |
| ≥ 20 | Low Risk |
| < 20 | Minimal Risk |

On **Cloud → Posture** the score is computed from **open** findings only (suppressed ones are excluded), and summed across all accounts. On the connector **Overview** tab it uses the counts stored in the scan result. For Azure, those stored counts include suppressed findings (see the Azure page).

**Checks passing** (Posture header) = `passed / (open findings + passed)`, as a percentage across all accounts. The meter is green at ≥ 90 %, amber at ≥ 70 %, red below.

### 4.3 New-critical alerts

After each **scheduled** CSPM scan, `alertNewCriticalFindings` compares the new result with the previous stored one. Every open `critical` finding whose (lower-cased title, resource) was not present before raises an alert:

- Title `[CSPM] New critical misconfiguration: <finding title>`, severity 5, event type `cloud.cspm`, host = account, subscription or project.
- Event key `cspm:new:<hash(provider|scope|title|resource)>`.
- Nothing is raised on the very first scan for a connector. Manual **Run Scan** does not raise these alerts. It does replace the stored result, so a critical that first appears in a manual scan is never alerted.

### 4.4 Scan history

Every write of a `cspm:<provider>:<id>` setting also inserts the severity counts into `cloud_scan_history`. Rows older than 180 days are deleted. `GET …/{id}/cspm/history?days=N` (1–180, default 90) feeds the trend line at the top of the **Overview** tab ("Critical + high over N scans"). The line appears after two scans.

### 4.5 Finding suppression

| Provider | Applies to | Storage | API | UI |
|---|---|---|---|---|
| AWS | CSPM findings. Applied inside the scan, so counts, CIS and compliance exclude them. | setting `suppress:aws:rules` | `GET/POST/DELETE /api/v1/cloud-connectors/suppress/aws` (POST/DELETE admin) | None |
| Azure | CSPM findings (marked `suppressed` after counting) | table `azure_suppress_rules` | `…/suppress/azure` | None |
| GCP | **No CSPM finding suppression.** The GCP rules suppress signature alerts (section 3.1). | settings `suppress:gcp:*` | `…/suppress` | Rules page |

AWS and Azure rules match on optional account or subscription, title substring, resource prefix, category, severity and expiry.

## 5. CIS benchmark and compliance mapping

| | AWS | Azure | GCP |
|---|---|---|---|
| Benchmark | 28 internal controls (IAM-, STO-, LOG-, NET-) evaluated from the CSPM result | 33 live checks, "inspired by CIS Azure Foundations v2.0; control IDs are internal" | About 35 live checks, subset of CIS GCP Foundation v2.0 |
| Run | Automatically after each scheduled CSPM, or **Run Assessment** (which runs a fresh CSPM) | **Run Assessment** only | **Run Assessment** only |
| Statuses | PASS / FAIL / UNKNOWN | PASS / FAIL / UNKNOWN | PASS / FAIL / UNKNOWN / NOT_APPLICABLE |
| Score | passed ÷ (passed + failed) | passed ÷ (passed + failed) | Single project: passed ÷ **all** controls (UNKNOWN and N/A count as not passed). Several projects: passed ÷ (passed + failed). |

Compliance mapping covers four frameworks: **SOC2, PCI-DSS (v4.0), ISO27001 (2022), NIST-800-53 (Rev5)**.

- **GCP and Azure** (`MapToCompliance`): each of the 35 controls lists finding categories and resource types, plus a severity threshold. A control is FAIL if any open finding matches. It is NOT_ASSESSED if a check that feeds it is in `not_assessed`, or if no check maps to it. Otherwise it is PASS. Generated after each scheduled CSPM, or by **Remap Compliance** from the stored CSPM result.
- **AWS** (`AWSComplianceFromCIS`): each of the 40 controls lists benchmark control IDs. A control is FAIL if all of them fail, PARTIAL if some fail, NOT_ASSESSED if none fail but some are UNKNOWN, otherwise PASS. Generated from the stored CIS result.
- Framework score = passed ÷ (total − not assessed). Each report carries a disclaimer: an indicative mapping, not an audit or attestation.

Provider pages list the controls.

## 6. Alerts produced by the cloud subsystem

| Source | Title pattern | Event type on the alert | Dedup key |
|---|---|---|---|
| Signatures | `[<MITRE>] <rule name>` | the event's type | `sig:<id>:host:<host>:h:<hour>` |
| GCP correlation | `[<MITRE>] [CORR] …` | `cloud.gcp_correlation` | per rule, principal, hour |
| Azure correlation | `[<MITRE>] [CORR] …` | `cloud.azure_correlation` | `corr:az:<id>:host:<host>:p:<principal>:h:<hour>` |
| AWS sequences | `CORR-SEQ-AWS-*` titles | sequence correlator | correlator key |
| Baselines | `[<MITRE>] [ANOM] …` | `cloud.<provider>_anomaly` | per rule, principal, IP or service, hour |
| New CSPM critical | `[CSPM] New critical misconfiguration: …` | `cloud.cspm` | `cspm:new:<hash>` |
| Inventory deletion (GCP, Azure) | `[T1485] … Critical Asset/Resource Disappeared from Inventory` | `cloud.gcp_assets` / `cloud.azure_assets` | per resource per day |

All alerts appear in **Detect → Alerts** and go through the same store-level deduplication.

## 7. Console pages

The rail entry is **Cloud → Posture** (`/cloud`). The page has three tabs.

### 7.1 Posture header

- State pill: "N critical findings", "N high findings", "No critical or high findings", "No open findings" or "No accounts connected".
- Sub-line: number of providers and accounts, and "Last assessment <relative time>".
- Numbers: **Risk score** (/100, lower is better), **Checks passing** (%), **Open findings**, **Resources affected** (distinct resources with open findings), **Accounts**, **By severity** bars.
- Buttons: **Reload**, **Export** (CSV: severity, status, title, provider, account, resource, resource_type, area, detected), **Connect account** (opens the third tab).

The data comes from `GET /cloud-connectors` plus one `GET …/{id}/cspm` per connector. Only the last stored scan of each connector is used.

### 7.2 Findings tab

- Facets: **Severity**, **Status** (Open / Suppressed; Open is preselected), **Provider** (only when more than one provider exists), **Account** (top 12), **Area** (category).
- Filter box: free text over title, resource, account and description, plus `severity:critical,high` and `status:` tokens.
- Table columns: Severity, Finding, Account, Resource, Area (hover shows the CIS section from a fixed category map), Detected. Rows are sorted by severity, then scan time. At most 500 rows are shown.
- Clicking a row opens the **finding page** `/cloud/findings/<connector>/<finding id>`. It shows details (account, resource and type, area, benchmark, MITRE, check ID, description), remediation, **Same resource** (other findings on the same resource) and **Same check elsewhere** (same title in any account). If the finding is no longer in the latest scan, the page reads "Finding not found – It may have been fixed and dropped from the latest assessment."

### 7.3 Accounts tab

One row per connector: **State** (Error, Not scanned, Critical, High, Medium, OK; hover shows the last error), **Account**, **Provider**, **Critical**, **High**, **Open**, **Risk** (0–100 meter), **Last scan**. Clicking a row opens that account in the third tab.

### 7.4 Accounts and scans tab (per-account workspace)

Left sidebar: "Cloud Accounts" with the count and the number healthy, each connector's status, and **Add account** buttons per provider.

Connector header: provider, label or account ID, status badge, a critical or findings badge from the last scan, **Sync now**, **Import org accounts** (AWS only), and **Disconnect**.

| Tab | What it shows | Data source |
|---|---|---|
| **Overview** | Trend line, last scan time and duration, SCC/Defender badges, **AI Summary** (LLM executive summary of the top 12 critical and high findings), **Run Scan**, failed checks with role hints, risk gauge, Critical/High/Medium/Low/Passed/Assets tiles, "Findings by Category" bars, "Compliance Posture" bars, SCC or Defender status | CSPM result |
| **Asset Graph** | Asset Inventory grouped by resource type. All, Issues or Clean filter when inventory exists. Detail pane with the findings for the selected resource. **Full Inventory** button (GCP and Azure only). | inventory + CSPM |
| **Attack Surface** | Four cards: Open Firewall Rules / Open NSG Rules, Public IPs / Exposed VMs, Public Storage, Exposed Databases, plus "All Network & Exposure Findings". Selected by resource type and title keywords ("public", "internet", "0.0.0.0", "alluser"). | CSPM result |
| **Event Timeline** | Up to 500 newest events from this connector's agent IDs, grouped by day, with severity and type filters, search, and a detail pane | `GET /api/v1/events?agent_id=…` |
| **Deep Dive** | IAM, Storage, Compute and Network explorers that group findings by keyword rules | CSPM result |
| **Blast Radius** | Principal list with **Principals**, **Attack Paths**, **Priv Esc** and **Public Exp.** counters, and a focus graph of what a selected principal reaches. **Run Analysis** button. | blast result |
| **CIS Benchmark** | Score, per-section percentages, status and section filters, control cards with evidence and remediation. **Run Assessment** button. | CIS result |
| **Compliance** | Four framework score cards (% compliant, passed and failed), framework tabs, control cards with FAIL first. **Remap Compliance** button. | compliance report |

Notes on the Overview tab:

- The "Compliance Posture" bars on this tab are an **estimate** made in the browser from finding categories and `passed`. They are not the compliance report. For AWS connectors they are labelled with the GCP names ("CIS GCP 1.3").
- The tab shows data only when the result has `project_id` or `subscription_id`. AWS connectors without an Account ID never show results here (see [configuration-aws.md](configuration-aws.md)).
- The AI prompt calls every non-Azure connector "GCP".

`cspm.jsx` also contains a `CSPMDashboard` component and `events.jsx` a `CloudEventsAlerts` component. Neither is used by any page.

*Implemented in:* `pages/Cloud.jsx`, `pages/cloud/PostureOverview.jsx`, `FindingPage.jsx`, `connectors.jsx`, `overview.jsx`, `deepdive.jsx`, `blast.jsx`, `compliance.jsx`, `events.jsx`, `shared.jsx`.

## 8. Limits common to all providers

| Limit | Value |
|---|---|
| Sync interval / attempt timeout / attempts | 5 min / 3 min / 3 |
| CSPM interval / scheduled timeout | 6 h / 30 min per connector |
| Manual CSPM timeout | 15 min (GCP, Azure), 3 min (AWS) |
| Raw event size | 256 KiB, then replaced by a stub |
| Event Timeline | 500 events per source query, 500 shown |
| Findings table | 500 rows shown |
| Scan history retention | 180 days |
| Source status | In memory, lost on restart |
