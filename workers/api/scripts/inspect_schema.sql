-- Read-only inspection of the existing GomoGie D1 schema.
-- Run in Cloudflare D1 Console. These statements do not modify data.

SELECT name, sql
FROM sqlite_master
WHERE type = 'table'
  AND name NOT LIKE 'sqlite_%'
ORDER BY name;

PRAGMA table_info(conversations);
PRAGMA table_info(conversation_members);
PRAGMA table_info(messages);
PRAGMA table_info(users);
PRAGMA table_info(profiles);
PRAGMA table_info(media_assets);
PRAGMA table_info(post_media);
