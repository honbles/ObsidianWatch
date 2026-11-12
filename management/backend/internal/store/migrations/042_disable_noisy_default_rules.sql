-- 042: "Privileged Logon" alerts High on every elevated logon, which on a
-- normal workstation is every login. The MITRE signatures (brute force,
-- new admin, RDP, ...) cover the cases that matter. Re-enable in Alert Rules.
UPDATE alert_rules SET enabled = FALSE
WHERE name = 'Privileged Logon' AND created_by = 'system';
