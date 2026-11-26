-- GomoGie query efficiency indexes.
-- Additive only. Apply once after the D1 daily quota resets or after upgrading Workers.
-- These indexes target the high-frequency feed, reaction, comment, follow,
-- notification and publisher discovery query paths.

CREATE INDEX IF NOT EXISTS idx_posts_public_feed
  ON posts(status, visibility, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_user_feed
  ON posts(user_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_reactions_post
  ON reactions(post_id);
CREATE INDEX IF NOT EXISTS idx_comments_post_status_created
  ON comments(post_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_follows_follower_status_following
  ON follows(follower_id, status, following_id);
CREATE INDEX IF NOT EXISTS idx_follows_following_status_follower
  ON follows(following_id, status, follower_id);

CREATE INDEX IF NOT EXISTS idx_notifications_recipient_created
  ON notifications(recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_recipient_read
  ON notifications(recipient_id, is_read);

CREATE INDEX IF NOT EXISTS idx_gomogie_news_source_status_published
  ON gomogie_news_items(source_id, status, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_gomogie_news_status_type_published
  ON gomogie_news_items(status, content_type, published_at DESC);
