-- Additive OAuth identity and short-lived login handoff storage.
CREATE TABLE IF NOT EXISTS gomogie_oauth_identities (
  provider TEXT NOT NULL CHECK (provider IN ('google','facebook')),
  provider_user_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (provider, provider_user_id),
  UNIQUE (provider, user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_gomogie_oauth_identities_user
  ON gomogie_oauth_identities(user_id);

CREATE TABLE IF NOT EXISTS gomogie_oauth_states (
  state_hash TEXT PRIMARY KEY,
  provider TEXT NOT NULL CHECK (provider IN ('google','facebook')),
  code_verifier TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gomogie_oauth_states_expiry
  ON gomogie_oauth_states(expires_at);

CREATE TABLE IF NOT EXISTS gomogie_oauth_handoffs (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_gomogie_oauth_handoffs_expiry
  ON gomogie_oauth_handoffs(expires_at);
