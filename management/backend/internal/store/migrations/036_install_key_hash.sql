-- F-03: install keys are stored as SHA-256 hashes and shown once at
-- creation/regeneration. Existing plaintext keys are converted in place.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS install_key_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_agents_install_key_hash ON agents(install_key_hash);
UPDATE agents
   SET install_key_hash = encode(digest(install_key, 'sha256'), 'hex'),
       install_key = NULL
 WHERE install_key IS NOT NULL AND install_key <> '' AND install_key_hash IS NULL;
