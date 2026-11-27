-- Ensure all configured first-party and verified Malaysian publisher feeds are active.
INSERT INTO gomogie_news_sources (id,name,feed_url,language,active,created_at) VALUES
('mlstudios-video','ML Studios','https://www.youtube.com/feeds/videos.xml?channel_id=UCSkOqbajcG6-jguycOHzhDg','ms',1,CURRENT_TIMESTAMP),
('aphd-video','APHD Channel','https://www.youtube.com/feeds/videos.xml?channel_id=UChpjlRq-Ikx8JRUiRauIAJg','ms',1,CURRENT_TIMESTAMP),
('siakapkeli-video','Siakap Keli','https://www.youtube.com/feeds/videos.xml?channel_id=UCo5TWROsmkTHVhzmFUW94oA','ms',1,CURRENT_TIMESTAMP),
('astroawani-video','Astro AWANI','https://www.youtube.com/feeds/videos.xml?channel_id=UC5dYmq91e5_g54krpO06NJw','ms',1,CURRENT_TIMESTAMP),
('buletintv3-video','Buletin TV3','https://www.youtube.com/feeds/videos.xml?channel_id=UC2p8wkJVSjsMsRv0MjTikgA','ms',1,CURRENT_TIMESTAMP),
('kinitv-video','KiniTV','https://www.youtube.com/feeds/videos.xml?channel_id=UC9ULnkwvyofZ_sWrzRpyvrg','ms',1,CURRENT_TIMESTAMP),
('thestar-video','The Star','https://www.youtube.com/feeds/videos.xml?channel_id=UCpWvshQVx1d7BqCsPnVuNIw','en',1,CURRENT_TIMESTAMP),
('fmt-video','Free Malaysia Today','https://www.youtube.com/feeds/videos.xml?channel_id=UC2CzLwbhTiI8pTKNVyrOnJQ','en',1,CURRENT_TIMESTAMP)
ON CONFLICT(id) DO UPDATE SET
 name=excluded.name,
 feed_url=excluded.feed_url,
 language=excluded.language,
 active=1;
