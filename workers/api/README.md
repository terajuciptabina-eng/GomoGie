# GomoGie Cloudflare Workers API

This Worker targets the existing `gomogie-db` D1 schema. It does not create, drop, or rename the user's existing tables.

## Implemented routes

- `GET /health/live` — Worker liveness.
- `GET /health/ready` — D1 connectivity.
- `POST /v1/auth/register` — account and profile creation; closed by default until release safeguards are approved.
- `POST /v1/auth/login` — login by email or username.
- `GET /v1/auth/me` — authenticated account/profile.
- `GET /v1/feed` — published public posts.
- `POST /v1/posts` — create a post.
- `POST /v1/posts/:postId/reactions` and `DELETE` — add/remove reaction.
- `POST /v1/posts/:postId/comments` — add a comment.
- `POST /v1/users/:username/follow` and `DELETE` — follow/unfollow.

## Schema verified from Cloudflare D1 Console screenshots

The API uses the existing table/column names:

- `users`: id, email, username, password_hash, status, created_at, updated_at
- `profiles`: user_id, display_name, bio, avatar_url, cover_url, website, location, is_private, created_at, updated_at
- `posts`: id, user_id, content, visibility, status, comments_enabled, created_at, updated_at
- `reactions`: user_id, post_id, reaction_type, created_at
- `comments`: id, post_id, user_id, parent_id, content, status, created_at, updated_at
- `follows`: follower_id, following_id, status, created_at
- `media_assets`, `post_media`, `conversations`, `conversation_members`, `messages`, `notifications`, `reports`

The D1 screenshots show these are SQLite/D1 tables. The PostgreSQL migration under `backend/migrations` is a separate, unused alternative and must not be applied to this D1 database.

## Configure and deploy

1. Create/select the Worker named `gomogie-api` in Cloudflare Workers & Pages.
2. Add a D1 database binding named `DB` pointing to the existing `gomogie-db` database. If using Wrangler, copy the database ID from the D1 database details into `wrangler.toml`.
3. Set `ALLOWED_ORIGINS` to the exact GitHub Pages origin.
4. Set a strong secret named `JWT_SECRET` (at least 32 characters) through Cloudflare Worker Secrets. Never commit it to Git.
5. Deploy this Worker from this directory using Wrangler after authenticating the Cloudflare account.

Example commands from this directory:

```sh
npm install --save-dev wrangler
npx wrangler login
npx wrangler secret put JWT_SECRET
npx wrangler deploy
```

Do not paste credentials, API tokens, database IDs containing secrets, or the JWT secret into chat or Git.

## Security hardening applied

The current Worker source validates JWT structure and claims, checks that the account is still active in D1 on protected requests, bounds JSON request bodies to 64 KiB, and adds baseline response security headers. See [API security audit](../../docs/API_SECURITY_AUDIT.md) for the exact scope and remaining release blockers.

## Current limits

- Public registration is disabled by default using `ALLOW_REGISTRATION = "false"`. Do not enable it until rate limiting, email verification, account recovery and security testing are complete.

- Email verification and password reset are not implemented.
- Access tokens last 15 minutes; refresh tokens and server-side session revocation are not implemented.
- Public feed currently returns public posts only. A personalized Following feed and private/follower visibility enforcement still need implementation.
- Media upload, R2 delivery, image processing, video transcoding, messaging, notifications and moderation APIs are not implemented yet.
- Configure Cloudflare rate limiting before public exposure. The current Worker code does not yet bind to a rate-limiting namespace.
- Do not expose this API to public registration until security review, abuse controls and account recovery are complete.

A successful readiness response proves only that the Worker can query D1. It does not mean the whole social platform is production-ready.
