# GomoGie — Cloudflare D1 cutover

## Decision status

The project previously added a Fastify + PostgreSQL backend foundation. The current Cloudflare setup has a D1 database with tables created manually in the Cloudflare Console. These are two different database engines and their schemas are not interchangeable.

For the current Cloudflare-first path, the production API target is Cloudflare Workers + D1. The PostgreSQL backend remains an isolated alternative and must not be connected to the D1 database.

## What is now in the repository

- A Cloudflare Worker entry point.
- A D1 binding configuration template.
- Live and readiness endpoints.
- CORS allowlist configuration.
- A database-schema inspection gate before implementing data operations.

## Existing D1 schema verification

The user supplied Cloudflare D1 Console screenshots showing the actual table definitions. The Worker has been aligned to the visible columns in `users`, `profiles`, `posts`, `reactions`, `comments` and `follows`, with the remaining messaging/media tables identified for later implementation. Existing D1 tables must not be dropped or recreated merely to match the old PostgreSQL model.

## Delivery sequence

1. Verify actual D1 schema from `sqlite_master`.
2. Implement D1-native repository functions and parameterized SQL.
3. Add authentication with password hashing, short-lived access tokens, refresh/revocation strategy and rate limits.
4. Add profile, feed, post, reaction, comment and follow endpoints.
5. Add object-storage upload authorization only after R2 bucket configuration and CORS are verified.
6. Connect the frontend through an explicit API base URL.
7. Run migration, API, security and mobile browser acceptance tests.

## Current limitation

The Worker foundation is not yet a complete social API. No production deployment or frontend integration is claimed. Cloudflare account access, D1 database ID and deployed Worker URL remain owner-controlled configuration.
