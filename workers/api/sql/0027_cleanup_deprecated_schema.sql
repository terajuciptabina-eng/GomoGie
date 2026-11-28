-- Remove the retired feature data and schema from the production database.
-- Preserve ordinary text posts; remove only empty posts that existed solely for this feature.
DELETE FROM notifications
WHERE entity_id IN (
  SELECT p.post_id
  FROM gomogie_polls p
  JOIN posts po ON po.id=p.post_id
  WHERE trim(po.content)=''
);
DELETE FROM posts
WHERE id IN (
  SELECT post_id FROM gomogie_polls
)
AND trim(content)='';

DROP TABLE IF EXISTS gomogie_poll_votes;
DROP TABLE IF EXISTS gomogie_poll_options;
DROP TABLE IF EXISTS gomogie_polls;
