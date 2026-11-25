-- Broad, open-ended discovery sources: global, Malaysia, viral, topical and community feeds.
INSERT OR IGNORE INTO gomogie_news_sources (id,name,feed_url,language,active,created_at) VALUES
('google-my-ms','Google News Malaysia','https://news.google.com/rss?hl=ms&gl=MY&ceid=MY:ms','ms',1,CURRENT_TIMESTAMP),
('google-my-en','Google News Malaysia','https://news.google.com/rss?hl=en-MY&gl=MY&ceid=MY:en','en',1,CURRENT_TIMESTAMP),
('google-global','Google News Global','https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en','en',1,CURRENT_TIMESTAMP),
('google-viral-ms','Google News Trending','https://news.google.com/rss/search?q=(viral+OR+trending+OR+popular+OR+populariti)+when:1d&hl=ms&gl=MY&ceid=MY:ms','ms',1,CURRENT_TIMESTAMP),
('google-entertainment','Google News Entertainment','https://news.google.com/rss/search?q=(entertainment+OR+celebrity+OR+film+OR+music)+when:1d&hl=en-US&gl=US&ceid=US:en','en',1,CURRENT_TIMESTAMP),
('google-tech','Google News Technology','https://news.google.com/rss/search?q=(technology+OR+AI+OR+gaming)+when:1d&hl=en-US&gl=US&ceid=US:en','en',1,CURRENT_TIMESTAMP),
('google-sports','Google News Sports','https://news.google.com/rss/search?q=(sports+OR+football+OR+badminton)+when:1d&hl=en-US&gl=US&ceid=US:en','en',1,CURRENT_TIMESTAMP),
('reddit-popular','Reddit Popular','https://www.reddit.com/r/popular/.rss','en',1,CURRENT_TIMESTAMP),
('reddit-videos','Reddit Videos','https://www.reddit.com/r/videos/.rss','en',1,CURRENT_TIMESTAMP),
('reddit-malaysia','Reddit Malaysia','https://www.reddit.com/r/malaysia/.rss','en',1,CURRENT_TIMESTAMP),
('hackernews-top','Hacker News','https://news.ycombinator.com/rss','en',1,CURRENT_TIMESTAMP);
