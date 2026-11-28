-- GomoGie video posts (additive D1 migration)
-- Apply to the existing gomogie-db before deploying the updated Worker.

CREATE TABLE IF NOT EXISTS gomogie_video_assets (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL CHECK (mime_type = 'video/mp4'),
  size_bytes INTEGER NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 52428800),
  status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('ready','deleted')),
  created_at TEXT NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_gomogie_video_owner
  ON gomogie_video_assets(owner_id,created_at);
CREATE TABLE IF NOT EXISTS gomogie_post_videos (
  post_id TEXT PRIMARY KEY,
  video_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (video_id) REFERENCES gomogie_video_assets(id) ON DELETE CASCADE
);
