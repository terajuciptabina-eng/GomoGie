CREATE TABLE IF NOT EXISTS gomogie_message_files (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  file_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gomogie_message_files_owner ON gomogie_message_files(owner_id);
CREATE TABLE IF NOT EXISTS gomogie_message_attachments (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  attachment_type TEXT NOT NULL CHECK(attachment_type IN ('image','video','file')),
  media_id TEXT,
  video_id TEXT,
  file_id TEXT,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
  UNIQUE(message_id,position)
);
CREATE INDEX IF NOT EXISTS idx_gomogie_message_attachments_message ON gomogie_message_attachments(message_id,position);
