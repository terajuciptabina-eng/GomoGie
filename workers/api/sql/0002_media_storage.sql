-- GomoGie media storage schema (additive migration)
-- Safe to apply to the existing D1 database. Does not alter or delete existing tables.
-- Apply once before deploying the Worker media routes.

CREATE TABLE IF NOT EXISTS gomogie_media_assets (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('avatar','cover','post')),
  object_key TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL CHECK (mime_type IN ('image/jpeg','image/png','image/webp','image/gif')),
  size_bytes INTEGER NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 8388608),
  status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('ready','deleted')),
  created_at TEXT NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_gomogie_media_owner
  ON gomogie_media_assets(owner_id, purpose, created_at);

CREATE TABLE IF NOT EXISTS gomogie_post_media (
  post_id TEXT NOT NULL,
  media_id TEXT NOT NULL UNIQUE,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  PRIMARY KEY (post_id, media_id),
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (media_id) REFERENCES gomogie_media_assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_gomogie_post_media_post
  ON gomogie_post_media(post_id, position);
