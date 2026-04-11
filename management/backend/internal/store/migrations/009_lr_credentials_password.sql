-- 009_lr_credentials_password.sql
-- Add plaintext password column so guacd can authenticate via NLA/RDP.
ALTER TABLE lr_credentials ADD COLUMN IF NOT EXISTS password TEXT NOT NULL DEFAULT '';
