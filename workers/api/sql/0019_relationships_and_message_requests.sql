-- GomoGie social relationships. Additive and safe to re-run.
CREATE TABLE IF NOT EXISTS friend_requests (
  id TEXT PRIMARY KEY,
  requester_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK(requester_id <> recipient_id),
  UNIQUE(requester_id, recipient_id)
);
CREATE INDEX IF NOT EXISTS idx_friend_requests_recipient_status ON friend_requests(recipient_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_friend_requests_requester_status ON friend_requests(requester_id,status,created_at DESC);
CREATE TABLE IF NOT EXISTS gomogie_message_requests (
  id TEXT PRIMARY KEY,
  conversation_id TEXT NOT NULL UNIQUE REFERENCES conversations(id) ON DELETE CASCADE,
  requester_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined')),
  created_at TEXT NOT NULL,
  decided_at TEXT,
  CHECK(requester_id <> recipient_id)
);
CREATE INDEX IF NOT EXISTS idx_gomogie_message_requests_recipient ON gomogie_message_requests(recipient_id,status,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gomogie_message_requests_requester ON gomogie_message_requests(requester_id,status,created_at DESC);
