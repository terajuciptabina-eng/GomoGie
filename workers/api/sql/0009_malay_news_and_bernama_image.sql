-- Add official Astro AWANI Bahasa Melayu RSS source.
INSERT OR IGNORE INTO gomogie_news_sources (id,name,feed_url,language,active,created_at) VALUES ('astroawani-ms','Astro AWANI','https://www.astroawani.com/rss/latest/public','ms',1,CURRENT_TIMESTAMP);
-- Set the verified BERNAMA article image URL for the exact story.
UPDATE gomogie_news_items SET image_url='https://web14.bernama.com//storage/photos/2b7a901cdbdb1a3bc3506f40f4995b626b07091d129b3-large' WHERE title='More Discourse-based Programes, Culture of Mature And Open Dialogues Must Be Organised - PM Anwar';
