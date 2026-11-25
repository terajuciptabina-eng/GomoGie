-- Extend GomoGie News into a publisher content-discovery feed.
ALTER TABLE gomogie_news_items ADD COLUMN content_type TEXT NOT NULL DEFAULT 'article';
ALTER TABLE gomogie_news_items ADD COLUMN embed_url TEXT;
INSERT OR IGNORE INTO gomogie_news_sources (id,name,feed_url,language,active,created_at) VALUES
('mlstudios-articles','ML Studios','https://mlstudios.my/feed/','ms',1,CURRENT_TIMESTAMP),
('mlstudios-video','ML Studios','https://www.youtube.com/feeds/videos.xml?channel_id=UCSkOqbajcG6-jguycOHzhDg','ms',1,CURRENT_TIMESTAMP),
('aphd-video','APHD Channel','https://www.youtube.com/feeds/videos.xml?channel_id=UChpjlRq-Ikx8JRUiRauIAJg','ms',1,CURRENT_TIMESTAMP),
('siakapkeli-articles','Siakap Keli','https://siakapkeli.my/feed','ms',1,CURRENT_TIMESTAMP),
('siakapkeli-video','Siakap Keli','https://www.youtube.com/feeds/videos.xml?channel_id=UCo5TWROsmkTHVhzmFUW94oA','ms',1,CURRENT_TIMESTAMP);
