-- Store publisher-provided article image URLs for GomoGie Viral News.
ALTER TABLE gomogie_news_items ADD COLUMN image_url TEXT NOT NULL DEFAULT '';
