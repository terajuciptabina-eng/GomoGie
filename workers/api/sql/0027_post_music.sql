CREATE TABLE IF NOT EXISTS gomogie_post_music (
  post_id TEXT PRIMARY KEY,
  track_id TEXT NOT NULL,
  title TEXT NOT NULL,
  artist TEXT NOT NULL,
  art_url TEXT NOT NULL,
  stream_url TEXT NOT NULL,
  license TEXT NOT NULL,
  source TEXT NOT NULL,
  source_url TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
);
