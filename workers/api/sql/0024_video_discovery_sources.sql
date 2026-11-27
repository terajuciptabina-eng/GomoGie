-- Activate verified Malaysian publisher YouTube feeds for Watch Content Discovery.
INSERT INTO gomogie_news_sources (id,name,feed_url,language,active,created_at) VALUES
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
