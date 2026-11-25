-- Add reliable public publisher feeds and pause repeatedly blocked aggregators.
UPDATE gomogie_news_sources SET active=0 WHERE id IN
('google-my-ms','google-my-en','google-global','google-viral-ms','google-entertainment','google-tech','google-sports','reddit-popular','reddit-videos','reddit-malaysia','hackernews-top');

INSERT OR IGNORE INTO gomogie_news_sources (id,name,feed_url,language,active,created_at) VALUES
('bbc-world','BBC News World','https://feeds.bbci.co.uk/news/world/rss.xml','en',1,CURRENT_TIMESTAMP),
('bbc-top','BBC News','https://feeds.bbci.co.uk/news/rss.xml','en',1,CURRENT_TIMESTAMP),
('bbc-tech','BBC Technology','https://feeds.bbci.co.uk/news/technology/rss.xml','en',1,CURRENT_TIMESTAMP),
('bbc-sport','BBC Sport','https://feeds.bbci.co.uk/sport/rss.xml','en',1,CURRENT_TIMESTAMP),
('guardian-world','The Guardian World','https://www.theguardian.com/world/rss','en',1,CURRENT_TIMESTAMP),
('aljazeera-en','Al Jazeera English','https://www.aljazeera.com/xml/rss/all.xml','en',1,CURRENT_TIMESTAMP),
('npr-news','NPR News','https://feeds.npr.org/1001/rss.xml','en',1,CURRENT_TIMESTAMP),
('theverge-tech','The Verge','https://www.theverge.com/rss/index.xml','en',1,CURRENT_TIMESTAMP),
('techcrunch','TechCrunch','https://techcrunch.com/feed/','en',1,CURRENT_TIMESTAMP),
('wired-tech','WIRED','https://www.wired.com/feed/rss','en',1,CURRENT_TIMESTAMP),
('sciencedaily','ScienceDaily','https://www.sciencedaily.com/rss/all.xml','en',1,CURRENT_TIMESTAMP),
('ign-gaming','IGN','https://www.ign.com/rss/articles/feed','en',1,CURRENT_TIMESTAMP);
