-- 013_alert_rule_fields.sql
-- Adds granular filter fields to alert_rules:
--   command_line_match  — substring match on event command_line
--   src_ip_match        — substring match on event src_ip
--   dst_ip_match        — substring match on event dst_ip
--   dns_match           — substring match on event dst_ip when event_type=dns (domain name)
--   os_match            — exact match on event os (windows / linux / macos)
--   source_match        — substring match on event source (e.g. sshd, Sysmon, configmon)

ALTER TABLE alert_rules
    ADD COLUMN IF NOT EXISTS command_line_match TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS src_ip_match       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS dst_ip_match       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS dns_match          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS os_match           TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_match       TEXT NOT NULL DEFAULT '';
