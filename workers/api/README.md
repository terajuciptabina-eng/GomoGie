# GomoGie Cloudflare Workers API

This Worker targets the existing `gomogie-db` D1 schema. It does not create, drop, or rename the user's existing tables.

## Implemented routes

- `GET /health/live` — Worker liveness.
- `GET /health/ready` — D1 connectivity.
- `POST /v1/auth/register` — account and profile creation; closed by default until release safeguards are approved.
- `POST /v1/auth/login` — login by email or username.
- `GET /v1/auth/me` — authenticated account/profile.
- `GET /v1/feed` — published public posts.
- `GET /v1/feed?scope=following` — authenticated feed containing the current user's posts and posts from accepted follows, with public/followers visibility rules.
- `GET /v1/users/me/following` — authenticated list of accepted and pending follow relationships for session restoration.
- `GET /v1/feed?scope=following` — authenticated feed containing the signed-in user's own posts plus public/follower-audience posts from accounts they follow with an accepted relationship. Pending private-account requests do not expose posts.
- `POST /v1/posts` — create a post.
- `POST /v1/posts/:postId/reactions` and `DELETE` — add/remove reaction.
- `GET /v1/posts/:postId/comments` — read comments on public posts.
- `POST /v1/posts/:postId/comments` — add a comment.
- `GET /v1/notifications` — list the authenticated user’s notifications and unread count.
- `GET /v1/conversations` — list the authenticated user's direct conversations and unread counts.
- `POST /v1/conversations` — find or create a direct conversation by recipient username.
- `GET /v1/conversations/:conversationId/messages` — read the latest messages; updates the member's `last_read_at`.
- `POST /v1/conversations/:conversationId/messages` — send a text message.
- `PATCH /v1/notifications/:notificationId/read` and `PATCH /v1/notifications/read-all` — mark notifications as read.
- `POST /v1/users/:username/follow` and `DELETE` — follow/unfollow.

New reactions, comments and accepted public follows create persistent notifications for the affected user. Self-actions do not create notifications.

## Schema verified from Cloudflare D1 Console screenshots

The API uses the existing table/column names:

- `users`: id, email, username, password_hash, status, created_at, updated_at
- `profiles`: user_id, display_name, bio, avatar_url, cover_url, website, location, is_private, created_at, updated_at
- `posts`: id, user_id, content, visibility, status, comments_enabled, created_at, updated_at
- `reactions`: user_id, post_id, reaction_type, created_at
- `comments`: id, post_id, user_id, parent_id, content, status, created_at, updated_at
- `follows`: follower_id, following_id, status, created_at
- `conversations`: id, type, title, created_by, created_at
- `conversation_members`: conversation_id, user_id, joined_at, last_read_at
- `messages`: id, conversation_id, sender_id, content, media_id, status, created_at, edited_at
- `media_assets`, `post_media`, `notifications`, `reports`

The D1 screenshots show these are SQLite/D1 tables. The PostgreSQL migration under `backend/migrations` is a separate, unused alternative and must not be applied to this D1 database.

## Media uploads

See [Media Upload — Implementation & Operations Guide](../../docs/MEDIA_UPLOAD.md) for the R2 architecture, additive D1 migration, upload API, security checks, deployment and acceptance tests. Image uploads require the configured MEDIA_BUCKET R2 binding and the 0002_media_storage.sql migration.

Implemented image routes:

- POST /v1/media — authenticated multipart image upload (avatar, cover, post; JPEG/PNG/WebP/GIF; maximum 8 MiB).
- GET /v1/media/:mediaId — public delivery for media marked ready.
- POST /v1/posts accepts an owned mediaId and attaches the uploaded image to the post.

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
- Access JWTs currently have a 30-day expiry and are renewed through the authenticated `/v1/auth/remember` endpoint. This is not a refresh-token rotation or server-side revocable session system.
- The public feed returns public posts. The authenticated Following feed returns the signed-in user's own posts and posts from accepted follow relationships; pending private-account requests do not expose posts. A complete privacy/visibility audit across every endpoint and surface is still required.
- Image upload and R2 delivery are implemented in the Worker source. They require the additive D1 media migration and an existing R2 bucket bound as MEDIA_BUCKET; see the media guide. Image moderation, resizing, EXIF stripping, quota enforcement, orphan cleanup, video upload and transcoding are not implemented. Direct text messaging is implemented, but attachments, group conversations, message editing/deletion, typing indicators, realtime delivery and push notifications are not implemented yet.
- Configure Cloudflare rate limiting before public exposure. The current Worker code does not yet bind to a rate-limiting namespace.
- Do not expose this API to public registration until security review, abuse controls and account recovery are complete.

A successful readiness response proves only that the Worker can query D1. It does not mean the whole social platform is production-ready.
