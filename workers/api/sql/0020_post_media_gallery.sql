-- Ordered mixed media attachments for a single post.
-- Backfill existing one-image and one-video posts without changing their media assets.
CREATE TABLE IF NOT EXISTS gomogie_post_attachments (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL,
  media_type TEXT NOT NULL CHECK (media_type IN ('image','video')),
  media_id TEXT,
  video_id TEXT,
  position INTEGER NOT NULL CHECK (position >= 0),
  created_at TEXT NOT NULL,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (media_id) REFERENCES gomogie_media_assets(id) ON DELETE CASCADE,
  FOREIGN KEY (video_id) REFERENCES gomogie_video_assets(id) ON DELETE CASCADE,
  CHECK (
    (media_type='image' AND media_id IS NOT NULL AND video_id IS NULL) OR
    (media_type='video' AND video_id IS NOT NULL AND media_id IS NULL)
  ),
  UNIQUE(post_id,position)
);
CREATE INDEX IF NOT EXISTS idx_gomogie_post_attachments_order
  ON gomogie_post_attachments(post_id,position);
INSERT OR IGNORE INTO gomogie_post_attachments (id,post_id,media_type,media_id,video_id,position,created_at)
SELECT lower(hex(randomblob(16))),post_id,'image',media_id,NULL,0,created_at
FROM gomogie_post_media;
INSERT OR IGNORE INTO gomogie_post_attachments (id,post_id,media_type,media_id,video_id,position,created_at)
SELECT lower(hex(randomblob(16))),post_id,'video',NULL,video_id,0,created_at
FROM gomogie_post_videos
WHERE NOT EXISTS (SELECT 1 FROM gomogie_post_attachments a WHERE a.post_id=gomogie_post_videos.post_id);
