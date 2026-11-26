-- GomoGie social relationships: explicit two-way friendships, separate from one-way follows.
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
CREATE INDEX IF NOT EXISTS idx_friend_requests_accepted_pair ON friend_requests(requester_id,recipient_id,status);

-- Existing conversations remain accepted. New non-friend conversations become message requests.
ALTER TABLE conversations ADD COLUMN status TEXT NOT NULL DEFAULT 'accepted' CHECK(status IN ('pending','accepted'));
ALTER TABLE conversations ADD COLUMN initiated_by TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE conversations ADD COLUMN request_decided_at TEXT;
CREATE INDEX IF NOT EXISTS idx_conversations_status_created ON conversations(status,created_at DESC);
