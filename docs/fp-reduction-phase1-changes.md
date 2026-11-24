# FP reduction: change summary

Written against `obsidianwatch-detection-fp-reduction-spec.md`.
**Not compiled or tested**: the authoring environment had no Go toolchain or network.
Run `go build ./... && go test ./...` in `management/backend`, `agents/linux`, `agents/macos`
(darwin) and `npm run build` in `management/frontend` before merging. Expect to fix a few
compile errors; the new tests encode the intended behaviour.

## Migrations
- `064_ioc_pulse_meta.sql` - OTX pulse id/name/size on `ioc_indicators`.
- `065_suppression_v2.sql` - new `endpoint_suppressions` columns (existing rows become `prefix`), `endpoint_suppression_hits`.

## IOC pipeline
- A1 agent (Linux): `collector/pkgverify.go`; `pkg_verified` / `pkg_name` on process events. dpkg (md5sums) and rpm (`rpm -qf`). No package manager = field absent (unknown).
- A2 `api/ioc_gate.go`: verified/signed -> Info; unknown + system path -> max Medium; explicit `pkg_verified=false` keeps severity; fleet prevalence (>= `ioc_hash_prevalence_hosts`, default 3, first seen >= 7 days) -> one step down. Switch: `ioc_known_good_enabled`.
- A3 `api/otx_score.go`: per-pulse confidence 5..85, 90-day expiry, inactive/expired indicators skipped, weekly full resync.
- A4 private/CGNAT IPs and popular domains dropped at ingest (embedded list; replace with Tranco top-10k).
- A5 Feodo recommended list 90, aggressive 65.
- A6 suppression applies to IOC (`IOC:<source>:<type>`) and Sigma (`SIGMA:<id>`) alerts.

## Rules
- Shared helpers: `api/match_helpers.go`; `api/linux_fp_rules.go`; `api/win_fp_rules.go`; `api/burst.go` (distinct-value sliding window for ransomware and Kerberoast bursts).
- Linux/macOS (7.1): all rows except M-T1543.004 (needs agent writer signing info).
- Windows (7.2): all rows except the AV-registered check for W-T1562.001c and the payload decode for W-T1059.001a.
- DC (7.3): Kerberoast (burst Sev 4 + single Sev 2 as DC-T1558.003b), AS-REP, DCSync GUIDs + allow-list; spray rule removed (CORR-AUTH-001 owns it); golden ticket observe-only.
- Metadata (7.4): `NET-IMDS-001` (Sev 4) and `NET-IMDS-002` (Sev 5, shell/interpreter/user-writable path), destination-field match, `imds_allowed_processes` setting. `L-T1078.004` removed; `C-NET-005` and `C-XCLOUD-010` are cloud-event only; endpoint network events get only the IMDS rules.
- Sigma `ParentImage` / `ParentCommandLine` aliases for Linux/macOS raw events.

## Observe mode (E)
`zz_endpoint_rule_meta.go` registers RuleMeta for every built-in endpoint rule, so they can be disabled / allow-listed / observed through `rule_settings`. Default observe: L-T1611b, L-DLP-010, L-T1087.001, L-T1590, L-T1560, L-T1222.002, L-T1105, L-T1548.001b, M-T1082, W-T1110, W-T1021.001, W-T1570, W-T1057, W-T1016, W-T1087, DC-T1558.001. Observe alerts are raised at Info severity.

## Suppression v2 (C)
Backend: `api/endpoint_suppress.go` (exact/prefix modes, image/parent/user/cmdline/file matchers, expiry required <= 365 days or explicit permanent, prefix >= 8 chars matching a registered ID, per-day hit counters, create/edit/delete audited, preview endpoint).
UI: `frontend/src/pages/Suppressions.jsx` (route `/suppressions`, sidebar under Detection) and a "Suppress this alert" button in the alert panel that pre-fills rule, host, process, parent and user.

## Agent argv (B2)
Linux collector and macOS ES exec events add `argv` (max 64 items, 512 bytes each) to the raw payload. `cmdline` is unchanged. The spec asked for 32 items / 4 KB; adjust the constants in `collector/process.go` and `collector/es_exec.go` if you want those limits.

## Known gaps
- W-T1562.001c AV-registered check, M-T1543.004 signing check, W-T1059.001a decode, Windows `signed_trusted`.
- Discovery-burst correlation: W-T1057/1016/1087 are observe-only instead.
- L-T1572 stateful variant, `installer_hosts` as a platform setting (hard-coded list now).
- Workstreams F (dedupe), G (other blind spots), the fleet-replay CLI and full corpus were not part of this pass.

## Files touched (diff against obsidianwatch_clean_53.zip)

New (21):
- agents/linux/internal/collector/pkgverify.go, pkgverify_test.go, argv_test.go
- management/backend/internal/api/ioc_gate.go, otx_score.go, match_helpers.go, linux_fp_rules.go, win_fp_rules.go, burst.go, imds_rule.go, zz_endpoint_rule_meta.go
- management/backend/internal/api tests: fp_reduction_test.go, win_fp_test.go, fx_fp_win_test.go, endpoint_suppress_v2_test.go
- management/backend/internal/store/migrations/064_ioc_pulse_meta.sql, 065_suppression_v2.sql
- management/frontend/src/pages/Suppressions.jsx
- docs/fp-reduction-phase1-changes.md

Modified (21):
- agents/linux/internal/collector/process.go (pkg_verified, argv); agents/macos/internal/collector/es_exec.go (argv)
- management/backend/internal/api: detection_engine.go (rules, IOC gate/prevalence/suppression, Sigma suppression, settings), endpoint_suppress.go (rewritten), cloud_sigs.go (C-NET-005, C-XCLOUD-010), threat_intel_engine.go (OTX), threat_intel_feeds.go (Feodo), sigma_eval.go (ParentImage aliases), sig_registry.go and handlers_detections.go (imds set), server.go (PUT and preview routes)
- management/backend/internal/api fixtures: sig_fixtures_test.go, sig_fixtures_linux_test.go, sig_fixtures_macos_test.go, sig_fixtures_win_test.go, sig_fixtures_dc_test.go
- management/backend/internal/store/threat_intel.go (pulse columns)
- management/frontend/src: App.jsx (route), components/Shell.jsx (nav), components/AlertPanel.jsx (Suppress button), pages/AuditLog.jsx (colours)

Removed rules (not files): L-T1078.004, DC-T1110.003.
Added rules: L-T1059.004d, L-T1611b, L-T1003.008b, W-T1059.001d, DC-T1558.003b, NET-IMDS-001, NET-IMDS-002.
