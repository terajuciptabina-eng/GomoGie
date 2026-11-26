-- Revocable login sessions. Apply once after migration 0015.
ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0;
