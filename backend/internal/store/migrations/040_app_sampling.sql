-- Application Monitoring: trace sampling counters (APM spec item 13). Per service, hour and keep reason: how many
-- traces were completed on the host ("seen") and how many were kept ("kept"), so loss from sampling is visible.
CREATE TABLE IF NOT EXISTS app_sampling_stats (
  hour       TIMESTAMPTZ NOT NULL,
  service_id BIGINT      NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  reason     TEXT        NOT NULL,
  seen       BIGINT      NOT NULL DEFAULT 0,
  kept       BIGINT      NOT NULL DEFAULT 0,
  PRIMARY KEY (service_id, reason, hour)
);
