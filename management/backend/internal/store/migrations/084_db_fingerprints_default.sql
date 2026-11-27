-- Database statement fingerprints are on by default (November 2026): the agent sends each statement with
-- every value removed on the host (WHERE id = 5 becomes where id = ?), so the Queries tab shows the real
-- query shape. Existing services switch too; a service can be set back to names only in its settings.
ALTER TABLE service_settings ALTER COLUMN db_statement_mode SET DEFAULT 'fingerprint';
UPDATE service_settings SET db_statement_mode = 'fingerprint' WHERE db_statement_mode = 'off';
