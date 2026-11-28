# GomoGie Cloudflare Workers API

This Worker targets the existing `gomogie-db` D1 schema. It does not create, drop, or rename the user's existing tables.

## Implemented routes

- `GET /health/live` — Worker liveness.
- `GET /health/ready` — D1 connectivity.
- `POST /v1/auth/register` — account and profile creation; closed by default until release safeguards are approved.
- `POST /v1/auth/login` — login by email or username.
- `GET /v1/auth/oauth/google/start` and `/v1/auth/oauth/facebook/start` — begin provider sign-in/sign-up.
- `GET /v1/auth/oauth/google/callback` and `/v1/auth/oauth/facebook/callback` — server-side provider callback and identity verification.
- `POST /v1/auth/oauth/exchange` — exchange a short-lived, single-use handoff code for a GomoGie JWT.
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
- `GET /v1/users/search?q=` — authenticated member search by username or display name.
- `GET /v1/friends` — list accepted two-way friendships.
- `GET /v1/friend-requests` — list incoming and outgoing friend requests.
- `POST /v1/users/:username/friend-request` — send a friend request; a reciprocal pending request is accepted.
- `POST /v1/friend-requests/:requestId/accept` and `/decline` — accept or decline an incoming request.
- `DELETE /v1/friends/:username` — remove an accepted friendship without changing follow relationships.
- `GET /v1/message-requests` — list incoming and outgoing non-friend message requests.
- `POST /v1/conversations/:conversationId/accept` and `/decline` — accept or delete a message request.


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

## Friends, followers and message requests (migration 0019)

Apply `sql/0019_relationships_and_message_requests.sql` to the existing `gomogie-db` D1 database before using the relationship endpoints. This migration is additive and safe to re-run.

- Friendships are explicit two-way relationships: a request becomes a friendship only after the recipient accepts it (or reciprocates an existing pending request).
- Follows remain independent one-way relationships. Mutual follows do not automatically create friendships, and removing a friend does not silently change either follow.
- Non-friends may start a direct conversation as a Message Request. The sender can send one introductory message; the recipient must accept before either side can continue.
- Existing direct conversations are treated as accepted and remain in the Messages inbox.
- Friends can start accepted direct conversations immediately.
- Connect UI groups Friends, Requests and Messages; friend requests and message requests are kept separate from the normal inbox.

## Communities

Additive D1 migration: `sql/0013_communities.sql`. Apply it before using the Communities API. Authenticated routes: `GET/POST /v1/communities`, `GET/PATCH/DELETE /v1/communities/:slug`, `POST /join`, `POST /leave`, `GET /members`, and `GET/POST /posts`. Visibility and membership checks are enforced by the Worker. Public communities are discoverable; private/approval communities are only disclosed to members/owners. The current API supports owner/member roles; moderator assignment and pending-request moderation UI are not yet exposed.

## Media uploads

See [Media Upload — Implementation & Operations Guide](../../docs/MEDIA_UPLOAD.md) for the R2 architecture, additive D1 migration, upload API, security checks, deployment and acceptance tests. Image uploads require the configured MEDIA_BUCKET R2 binding and the 0002_media_storage.sql migration.

Implemented image routes:

- POST /v1/media — authenticated multipart image upload (avatar, cover, post; JPEG/PNG/WebP/GIF; maximum 8 MiB).
- GET /v1/media/:mediaId — public delivery for media marked ready.
- POST /v1/posts accepts an owned mediaId and attaches the uploaded image to the post.

## Developer Console operations

The authenticated Developer Console exposes role-gated operations:

- `GET /v1/developer/system` — Owner-only D1 and R2 dependency checks.
- `GET /v1/developer/settings` — Owner-only safe runtime configuration summary; secrets are never returned.
- `GET /v1/developer/users?q=&status=&limit=&offset=` — Admin/Support/Owner account directory; returns public operational fields only, never email or credential hashes.
- `PATCH /v1/developer/users/:id/status` — Admin/Owner activate or deactivate a member account, revoking existing sessions and writing an audit record. Self-status changes and changes to another Developer account by non-Owner roles are blocked; accounts pending deletion cannot be changed.
- `GET /v1/developer/reports?status=open|reviewed|dismissed|actioned|all` — Admin/Moderator/Owner community-report queue.
- `PATCH /v1/developer/reports/:id` — Admin/Moderator/Owner report workflow status update, recorded in the developer audit log.
- `GET /v1/developer/analytics` — Admin/Analyst/Owner aggregate totals and 14-day user/post activity.
- `GET /v1/developer/audit?q=&action=&limit=&offset=` — Admin/Analyst/Owner searchable, paginated audit history.
- `GET/POST /v1/developer/admins`, role update and revoke — Owner-only access governance.

The frontend surfaces User Management, Community Reports, Platform Analytics, System Health and a safe runtime Platform Settings view according to the server-returned role capabilities. User Management supports account search and controlled activate/deactivate actions for Admin/Owner; it does not expose email, password hashes, permanent deletion or self-deactivation. The community report queue updates report workflow status only; it does not itself remove content or ban accounts. The system check is a dependency probe, not full observability or an uptime guarantee.

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

- Public registration is controlled by the deployment owner through `ALLOW_REGISTRATION`; do not change the configured value without the owner's explicit instruction.

- Email verification and password reset are not implemented.
- Access JWTs currently have a 30-day expiry and are renewed through the authenticated `/v1/auth/remember` endpoint. This is not a refresh-token rotation or server-side revocable session system.
- The public feed returns public posts. The authenticated Following feed returns the signed-in user's own posts and posts from accepted follow relationships; pending private-account requests do not expose posts. A complete privacy/visibility audit across every endpoint and surface is still required.
- Image upload and R2 delivery are implemented in the Worker source. They require the additive D1 media migration and an existing R2 bucket bound as MEDIA_BUCKET; see the media guide. Video upload and byte-range delivery are implemented in source and require migration 0003 plus Worker deployment; video transcoding, codec inspection, thumbnail generation, moderation, resizing, EXIF stripping, quota enforcement and orphan cleanup are not implemented. Direct text messaging is implemented, but attachments, group conversations, message editing/deletion, typing indicators, realtime delivery and push notifications are not implemented yet.
- Configure Cloudflare rate limiting before public exposure. The current Worker code does not yet bind to a rate-limiting namespace.
- Do not expose this API to public registration until security review, abuse controls and account recovery are complete.

A successful readiness response proves only that the Worker can query D1. It does not mean the whole social platform is production-ready.


## Viral News

- `GET /v1/news?mode=global` — global discovery feed.
- `GET /v1/news?mode=for-you` — personalised region/interests feed for signed-in members; anonymous requests receive global stories.
- `GET /v1/news/preferences` and `PUT /v1/news/preferences` — read/update member region and category interests.
- Cloudflare Cron Trigger ingests the configured BERNAMA English RSS source every 15 minutes.
- Additive D1 migration: `sql/0004_viral_news.sql`.
- News cards are attributed and link to the publisher. The system stores only RSS headlines and short descriptions; it does not copy full articles or publisher images. Confirm publisher rights before public/commercial launch.


## Account management (migration 0015)

Apply `sql/0015_account_management.sql` and then `sql/0016_session_revocation.sql` to the existing `gomogie-db` D1 database before deploying the updated Worker.

- `PUT /v1/account/username` — change username with current-password confirmation and uniqueness check.
- `PUT /v1/account/password` — change password after verifying the current password; other issued sessions are revoked.
- `POST /v1/account/logout-all` — revoke all other sessions after current-password confirmation; the current device receives a replacement token.
- `POST /v1/account/deactivate` — deactivate the account; a successful password login reactivates it.
- `POST /v1/account/delete` — schedule deletion after 30 days; a successful password login during the recovery window cancels the request.
- `PUT /v1/auth/me` now accepts `isPrivate` to update public/private profile visibility.

The existing 15-minute Cron Trigger also processes due deletion requests. At the end of the recovery period the Worker removes the member's posts, comments, reactions, follows, notifications, sent messages, memberships, and uploaded media, then anonymises the remaining account identity so foreign-key relationships in other members' records are not broken.

Email changes remain disabled until an email-verification delivery flow is configured. JWTs carry a database-backed session version. Password changes, deactivation, deletion requests and Log out all devices increment that version and revoke older tokens.


## Google and Facebook OAuth

OAuth is handled by this Worker; provider tokens and client secrets never reach the browser. The frontend receives a short-lived, one-time handoff code and exchanges it for the existing GomoGie JWT. OAuth state and handoff records are consumed atomically in D1 so concurrent callback or exchange requests cannot reuse the same code. Google ID tokens are signature-verified against Google's published signing keys and must have a verified email. OAuth state is bound to a short-lived HttpOnly/Secure/SameSite=Lax cookie. Login handoff codes expire after two minutes and are single-use.

Apply the additive migration before enabling the provider buttons:
```sh
npx wrangler d1 migrations apply gomogie-db --remote
```

Configure these Worker secrets (never commit their values):
```sh
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put FACEBOOK_APP_ID
npx wrangler secret put FACEBOOK_APP_SECRET
```

Register these exact redirect URIs with the providers:
- Google: `https://gomogie-api.terajuciptabina.workers.dev/v1/auth/oauth/google/callback`
- Facebook: `https://gomogie-api.terajuciptabina.workers.dev/v1/auth/oauth/facebook/callback`

The provider app must be configured for the appropriate web OAuth product and production/live mode before public use. Google requests only `openid email profile`; Facebook requests only `email,public_profile`. No Gmail, friend-list, photo or posting permissions are requested.

`OAUTH_FRONTEND_URL` is a non-secret Worker variable set in `wrangler.toml`. Keep it pointed at the canonical GitHub Pages app URL. New OAuth-created accounts obey `ALLOW_REGISTRATION`; existing linked identities can still sign in when registration is closed. A verified Google email may be linked to an existing account. Facebook identities are not auto-linked to an existing email; the user must use the original sign-in method until a separate authenticated account-link flow is implemented.

Do not deploy the Worker with OAuth enabled until migration 0028 is applied and all four provider secrets are configured. Missing credentials return a safe configuration error; they do not affect password login.
