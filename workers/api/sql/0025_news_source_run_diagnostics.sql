-- Persist the latest ingestion outcome for each news/video source.
-- This is separate from gomogie_news_sources so existing source rows remain compatible.
CREATE TABLE IF NOT EXISTS gomogie_news_source_runs (
  source_id TEXT PRIMARY KEY REFERENCES gomogie_news_sources(id) ON DELETE CASCADE,
  last_attempt_at TEXT NOT NULL,
  last_success_at TEXT,
  last_http_status INTEGER,
  feed_item_count INTEGER NOT NULL DEFAULT 0,
  accepted_count INTEGER NOT NULL DEFAULT 0,
  upsert_changes INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
