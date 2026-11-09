-- 026_lr_credentials_cleanup.sql
-- M-05: lr_credentials was storing both a bcrypt hash AND the plaintext
-- service-account password (009_lr_credentials_password.sql). Neither is
-- actually read back anywhere in the backend — handleInitiateSession only
-- checks that a row exists — so persisting the plaintext password just
-- sat there as a liability: anyone with DB/backup access got a live
-- credential for every agent's remote-access account. Dropping both
-- secret columns; "mode" records how the session authenticates
-- (e.g. "direct-shell" needs no credential at all) without storing one.
ALTER TABLE lr_credentials ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'direct-shell';
ALTER TABLE lr_credentials DROP COLUMN IF EXISTS password;
ALTER TABLE lr_credentials DROP COLUMN IF EXISTS password_hash;
