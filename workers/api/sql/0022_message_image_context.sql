-- Separate the logical media context from the legacy purpose CHECK constraint.
-- The original media table allows only avatar/cover/post in purpose. Message images
-- must be distinguishable for message attachment ownership checks without rebuilding
-- the table or disturbing existing post-media foreign keys.
ALTER TABLE gomogie_media_assets
  ADD COLUMN media_context TEXT NOT NULL DEFAULT 'post'
  CHECK (media_context IN ('avatar','cover','post','message'));

UPDATE gomogie_media_assets
SET media_context = purpose;
