-- Ensure APHD Channel remains enabled as a first-party Watch Content Discovery publisher.
INSERT INTO gomogie_news_sources (id,name,feed_url,language,active,created_at)
VALUES ('aphd-video','APHD Channel','https://www.youtube.com/feeds/videos.xml?channel_id=UChpjlRq-Ikx8JRUiRauIAJg','ms',1,CURRENT_TIMESTAMP)
ON CONFLICT(id) DO UPDATE SET
  name=excluded.name,
  feed_url=excluded.feed_url,
  language=excluded.language,
  active=1;
