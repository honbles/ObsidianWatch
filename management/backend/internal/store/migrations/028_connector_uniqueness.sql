-- 028_connector_uniqueness.sql
-- G-20 / DO-09: cloud_connectors and devops_connectors had no unique
-- constraint, so the code's "ON CONFLICT DO NOTHING" never fired: saving twice
-- created duplicate connectors polling the same account/org, and credential
-- rotation didn't reliably update the existing one. Keep the newest row per
-- natural key, drop the rest, then enforce uniqueness.
DELETE FROM cloud_connectors a USING cloud_connectors b
 WHERE a.provider = b.provider AND a.account_id = b.account_id AND a.id < b.id;
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_connectors_provider_account
    ON cloud_connectors (provider, account_id);

DELETE FROM devops_connectors a USING devops_connectors b
 WHERE a.provider = b.provider AND a.org = b.org AND a.id < b.id;
CREATE UNIQUE INDEX IF NOT EXISTS uq_devops_connectors_provider_org
    ON devops_connectors (provider, org);
