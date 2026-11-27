#!/bin/sh
# reset-data.sh - clear everything ObsidianWatch has collected, keep everything you configured.
#
#   ./reset-data.sh              back up the database, ask for confirmation, reset
#   ./reset-data.sh --yes        no confirmation prompt
#   ./reset-data.sh --no-backup  skip the backup (it can be large: it holds every event)
#
# CLEARED: events, alerts, agents (they re-register on their next report), discovered application services and
# all their data, cloud and code findings, commits, scans and jobs, threat-intel indicators (re-fetched),
# hunts, live-response sessions, network maps, response history, learned baselines and caches. Connectors and
# threat-intel sources are reset so they pull again from the start.
#
# KEPT: users and sessions' revocations, every setting, rules and their tuning, suppressions, connectors and
# their credentials, threat-intel sources, saved queries, code scan policies and triage decisions, links to issues
# already created on your code platform, agent enrollment (CA, tokens, enrolled identities: no agent needs
# re-enrolling), host tags and criticality, the audit log. Kept because they ARE configuration on a record that
# is otherwise data: agents with a tamper lock or a network isolation stay
# (their counters and location are reset), and application services with settings, reviewed routes, code links,
# merges or uploaded API specs stay (their collected data is cleared), so nothing you set is lost when they are
# rediscovered.
#
# Backups go to ./backups/ (ignored by git). Restore one (TimescaleDB needs the pre/post restore calls):
#   docker compose stop backend mgmt-api
#   docker compose exec -T timescaledb psql -U obsidianwatch -d obsidianwatch -c "SELECT timescaledb_pre_restore();"
#   docker compose exec -T timescaledb pg_restore -U obsidianwatch -d obsidianwatch --clean --if-exists < backups/<file>.dump
#   docker compose exec -T timescaledb psql -U obsidianwatch -d obsidianwatch -c "SELECT timescaledb_post_restore();"
#   docker compose start backend mgmt-api
set -eu
cd "$(dirname "$0")"

YES=""; BACKUP=1
for a in "$@"; do
  case "$a" in
    --yes|-y) YES=1 ;;
    --no-backup) BACKUP="" ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "unknown option $a (see --help)"; exit 1 ;;
  esac
done

# How SQL is run. OW_PSQL overrides it (used for testing against another database).
PSQL=${OW_PSQL:-"docker compose exec -T timescaledb psql -U obsidianwatch -d obsidianwatch -v ON_ERROR_STOP=1 -q -X"}
sql() { $PSQL "$@"; }
q() { sql -At -c "$1"; }

# ── Table classification ────────────────────────────────────────────────────────
# Every table must be in exactly one list. A table this script does not know stops it (a newer version added
# it; classify it here before resetting).
KEEP="schema_migrations users settings rule_settings alert_rules sigma_rules detection_signatures
azure_suppress_rules endpoint_suppressions code_triage_rules code_finding_triage code_finding_issues
threat_intel_sources saved_event_queries cloud_connectors devops_connectors agent_ca agent_enrollment_tokens
agent_identities lr_credentials agent_response_state host_meta service_settings app_route_payload_policy
app_route_payload_policy_log service_code_links app_service_merges service_declared_routes service_openapi
vuln_cpe_cache audit_log network_probe_devices agents services"
WIPE="events alerts alert_entities alert_related_events agent_location_history app_baselines app_client_stats
app_db_stats app_edge_stats app_metrics app_operations app_payloads app_route_children app_route_n1
app_route_stats app_sampling_stats app_traces service_edges service_instances service_route_params
service_routes service_versions error_group_hours error_groups cloud_scan_history code_fix_cache code_pr_checks
code_scan_jobs code_scan_results sast_results devops_commits endpoint_suppression_hits engine_cursors
file_hash_cache fleet_hunt_results fleet_hunts ioc_indicators lr_sessions lr_transcripts network_bandwidth
network_topology prevalence response_actions runtime_packages vuln_host_cve"

echo "== checking the database"
TABLES=$(q "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1") \
  || { echo "Cannot reach the database. Is the stack running (docker compose ps)?"; exit 1; }
UNKNOWN=""; PRESENT_WIPE=""
for t in $TABLES; do
  case " $(echo $KEEP) " in *" $t "*) continue ;; esac
  case " $(echo $WIPE) " in *" $t "*) PRESENT_WIPE="$PRESENT_WIPE $t"; continue ;; esac
  UNKNOWN="$UNKNOWN $t"
done
if [ -n "$UNKNOWN" ]; then
  echo "Stopped: this script does not know these tables:$UNKNOWN"
  echo "They were added after the script was written. Add each to KEEP or WIPE in reset-data.sh, then run it again."
  exit 1
fi

EVENTS=$(q "SELECT count(*) FROM events" 2>/dev/null || echo "?")
AGENTS=$(q "SELECT count(*) FROM agents" 2>/dev/null || echo "?")
ALERTS=$(q "SELECT count(*) FROM alerts" 2>/dev/null || echo "?")
SIZE=$(q "SELECT pg_size_pretty(pg_database_size(current_database()))")
echo "   database $SIZE: $EVENTS events, $ALERTS alerts, $AGENTS agents"

if [ -z "$YES" ]; then
  echo
  echo "This clears all collected data (events, alerts, agents, services' data, findings, scans) and keeps"
  echo "your configuration (users, settings, rules, connectors, enrollment). See the top of this script."
  printf "Type RESET to continue: "
  read -r answer
  [ "$answer" = "RESET" ] || { echo "Cancelled."; exit 1; }
fi

if [ -n "$BACKUP" ] && [ -z "${OW_PSQL:-}" ]; then
  mkdir -p backups
  f="backups/obsidianwatch-$(date +%Y%m%d-%H%M%S).dump"
  echo "== backing up the database to $f ($SIZE before compression; --no-backup skips this)"
  docker compose exec -T timescaledb pg_dump -U obsidianwatch -Fc obsidianwatch > "$f" 2>/dev/null \
    || { rm -f "$f"; echo "Backup failed (disk space?). Nothing was changed. Run with --no-backup to reset without one."; exit 1; }
  echo "   $(du -h "$f" | cut -f1) written"
fi

STOPPED=""
if [ -z "${OW_PSQL:-}" ]; then
  echo "== stopping the backend and management API while the data is cleared"
  docker compose stop backend mgmt-api >/dev/null
  STOPPED=1
fi
restart() { [ -n "$STOPPED" ] && { echo "== starting the backend and management API"; docker compose start backend mgmt-api >/dev/null; }; return 0; }
trap restart EXIT

echo "== clearing collected data"
sql <<SQL
BEGIN;
-- Tables that hold only collected data. One statement, so the foreign keys between them are satisfied.
TRUNCATE $(echo $PRESENT_WIPE | tr ' ' ',') RESTART IDENTITY;

-- Agents re-register on their next report. Kept: agents that carry security state (a tamper lock, or a network
-- isolation, which a new record would silently release); their counters and location are reset. Their
-- live-response record (mode and username for display, no secret) is removed with them and re-created when the
-- agent next reports it.
DELETE FROM agents a
 WHERE NOT COALESCE(a.tamper_locked, false)
   AND NOT EXISTS (SELECT 1 FROM agent_response_state s WHERE s.agent_id = a.id
                    AND (COALESCE(s.desired_isolated, false) OR COALESCE(s.isolated, false)));
UPDATE agents SET event_count = 0, superseded_by = NULL, superseded_at = NULL,
       lat = NULL, lng = NULL, location_accuracy = NULL, location_source = NULL, location_city = NULL,
       location_country = NULL, location_updated = NULL;
DELETE FROM agent_response_state s WHERE NOT EXISTS (SELECT 1 FROM agents a WHERE a.id = s.agent_id);

-- Application services are rediscovered from traffic. Kept: services with anything configured on them.
DELETE FROM services v
 WHERE NOT EXISTS (SELECT 1 FROM service_settings x WHERE x.service_id = v.id)
   AND NOT EXISTS (SELECT 1 FROM app_route_payload_policy x WHERE x.service_id = v.id)
   AND NOT EXISTS (SELECT 1 FROM service_code_links x WHERE x.service_id = v.id)
   AND NOT EXISTS (SELECT 1 FROM service_declared_routes x WHERE x.service_id = v.id)
   AND NOT EXISTS (SELECT 1 FROM service_openapi x WHERE x.service_id = v.id)
   AND NOT EXISTS (SELECT 1 FROM app_service_merges x WHERE x.alias_id = v.id OR x.canonical_id = v.id);

-- Network devices: kept only those marked known or given a location.
DELETE FROM network_probe_devices WHERE NOT COALESCE(is_known, false) AND COALESCE(location, '') = '';

-- Pull everything again from the start.
UPDATE cloud_connectors SET last_sync = NULL, last_error = NULL, event_count = 0, sync_cursor = '';
UPDATE devops_connectors SET last_sync = NULL, last_error = NULL, event_count = 0, sync_cursor = '';
UPDATE threat_intel_sources SET last_sync = NULL, last_error = NULL, ioc_count = 0;
UPDATE saved_event_queries SET sched_last_run = NULL, sched_last_count = 0;

-- Runtime state kept in the settings table (configuration keys are untouched).
DELETE FROM settings WHERE key LIKE 'correlator.state%' OR key LIKE 'incident.state.%' OR key LIKE 'baseline:%'
   OR key LIKE 'rca:%' OR key LIKE 'code.schedule.last.%' OR key IN ('ti.otx_last_sync', 'ti.otx_last_full_sync');

INSERT INTO audit_log (username, action, detail) VALUES ('reset-data.sh', 'data.reset', 'collected data cleared, configuration kept');
COMMIT;
SQL
echo "== done"
echo "   kept: $(q "SELECT count(*) FROM users") users, $(q "SELECT count(*) FROM cloud_connectors") cloud and $(q "SELECT count(*) FROM devops_connectors") code connectors, $(q "SELECT count(*) FROM agent_identities") enrolled agent identities, $(q "SELECT count(*) FROM agents") agents with configuration, $(q "SELECT count(*) FROM services") configured services"
echo "   agents reappear as they report (within a minute); connectors pull again on their next cycle (about 5 minutes)."
