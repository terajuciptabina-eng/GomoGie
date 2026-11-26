-- Account lifecycle and deletion requests. Additive only; existing accounts/data remain intact.
CREATE TABLE IF NOT EXISTS gomogie_account_deletion_requests (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  requested_at TEXT NOT NULL,
  scheduled_for TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','cancelled','completed'))
);
CREATE INDEX IF NOT EXISTS idx_gomogie_account_deletion_due
  ON gomogie_account_deletion_requests(status, scheduled_for);
