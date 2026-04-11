-- Add last_host to file_hash_cache to track which host last saw this hash
ALTER TABLE file_hash_cache ADD COLUMN IF NOT EXISTS last_host TEXT NOT NULL DEFAULT '';
