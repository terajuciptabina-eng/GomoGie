-- Server-side saved posts, shared across devices for each account.
CREATE TABLE IF NOT EXISTS gomogie_saved_posts (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  saved_at TEXT NOT NULL,
  PRIMARY KEY (user_id, post_id)
);
CREATE INDEX IF NOT EXISTS idx_gomogie_saved_posts_user_saved
  ON gomogie_saved_posts(user_id, saved_at DESC);
