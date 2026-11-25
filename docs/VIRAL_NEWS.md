# GomoGie Viral News

## Product behaviour
- Cloudflare Worker Cron Trigger runs every 15 minutes.
- Initial RSS adapter: BERNAMA English RSS.
- Only headline, short RSS description, publication date, category, region label and source URL are stored. Full articles are not copied.
- Cards are labelled GomoGie News and link to the original publisher.
- Home For You shows a compact auto-news block; Pulse offers For You and Global Trending.
- Signed-in members choose one region and one or more interests. Anonymous visitors see global headlines.
- Region is member-selected; device GPS is not read.
- Recent category volume is a discovery signal, not verified social virality or audience engagement.

## Data
- Additive D1 tables: gomogie_news_sources, gomogie_news_items, gomogie_news_preferences.
- Canonical URLs and source identifiers prevent duplicates.
- Old stories are cleaned after 30 days; only 14-day stories are served.
- RSS input is bounded, parsed as untrusted text and escaped by the client.
- No publisher images or full article text are copied.

## Source rights
BERNAMA provides a public RSS endpoint, but public availability is not a blanket copyright licence. Confirm permitted display of headlines and excerpts and attribution requirements before a public/commercial launch. Disable a source if permission is not confirmed. Do not add feeds whose terms prohibit commercial aggregation.

## Deployment and verification
1. Apply sql/0004_viral_news.sql to the existing gomogie-db D1 database.
2. Deploy the Worker with the 15-minute Cron Trigger.
3. Verify /health/ready and /v1/news?mode=global.
4. Sign in and save region/interests in Pulse; verify For You results.
5. Verify Home For You displays news and Following does not.
