# GomoGie Cloudflare Workers API foundation

This is the Cloudflare Workers + D1 deployment target for the Cloudflare account currently being configured.

## Current scope

- `GET /health/live`: confirms the Worker is running.
- `GET /health/ready`: confirms the D1 binding can execute a query.
- CORS is restricted to the configured static frontend origin.
- No user-facing write endpoints are exposed yet.

## Configure

1. In Cloudflare Dashboard, open Workers & Pages and create or select the Worker named `gomogie-api`.
2. Create/select the D1 database named `gomogie-db`.
3. Copy its database ID into `wrangler.toml`, replacing `REPLACE_WITH_D1_DATABASE_ID`.
4. Confirm the production frontend origin in `ALLOWED_ORIGINS`.
5. Deploy from this directory using Wrangler after authenticating the Cloudflare account.

Do not put API tokens, passwords, database secrets or private keys in this file or Git.

## Important database gate

The D1 tables were created manually in the Cloudflare Console. Before implementing account/feed mutations, inspect their exact columns and constraints. The PostgreSQL schema under `backend/migrations` is not compatible with D1 and must not be applied to D1.

Run this single read-only query in the D1 Console and retain the complete result:

```sql
SELECT name, sql
FROM sqlite_master
WHERE type = 'table'
  AND name NOT LIKE 'sqlite_%'
ORDER BY name;
```

This prevents the Worker from guessing column names or accidentally writing to an incompatible schema. Do not drop or recreate existing tables.

## Smoke tests after deployment

- `GET https://<worker-domain>/health/live`
- `GET https://<worker-domain>/health/ready`

A successful readiness response proves only that the Worker can query D1. It does not mean authentication, feeds, media, messaging or production security are complete.
