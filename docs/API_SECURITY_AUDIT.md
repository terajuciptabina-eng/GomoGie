# GomoGie API security audit

Date: 2026-11-25

## Scope

Source-reviewed: `workers/api/src/index.js`, `workers/api/wrangler.toml`, and `workers/api/README.md` on `main`. This is a source review, not a penetration test or a certification.

## Changes applied

- Public account registration is disabled by default with `ALLOW_REGISTRATION = "false"`; it returns HTTP 403 until explicitly enabled after release safeguards are in place.

- JWT verification now requires exactly three token segments and the expected `HS256` / `JWT` header.
- JWT claims are checked for a string subject, integer issue/expiry timestamps, a non-expired token, a reasonable issue time, and a maximum 15-minute lifetime.
- Protected API requests now check the current D1 account status. Disabled or missing accounts are rejected even if they still possess a previously issued token.
- Authentication is only evaluated on routes that require authentication; public health and feed routes no longer incur an unnecessary account lookup.
- JSON request bodies are bounded to 64 KiB before parsing.
- API responses include baseline browser security headers: `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`, and `Permissions-Policy`.

## Remaining release blockers

These items are not implemented and must be completed before public registration or a public production launch:

1. Rate limiting / abuse protection for registration, login, posting, comments, and reactions. Do not assume CORS is rate limiting.
2. Email verification, password reset, and account recovery.
3. Refresh-token or session management and revocation.
4. Security review of every authorization path, including private profiles, follower-only posts, follow requests, comment parent ownership, and moderation.
5. Complete frontend authentication and publishing integration, followed by end-to-end tests against the deployed Worker. The current frontend integration is read-only public feed loading with a demo fallback.
6. Media upload authorization, file validation, storage policy, and video processing before accepting user media.
7. Monitoring, alerting, backups, and operational recovery procedures.

- `PUT /v1/auth/me` updates allowlisted profile text fields and HTTPS image URLs for the authenticated account. This is not a file-upload endpoint.\n\n## Important behavior

- `GET /v1/feed` returns only posts marked `published` and `public`. `GET /v1/feed?scope=following` requires authentication and returns the current user's published posts plus posts from accepted follows with `public` or `followers` visibility. `GET /v1/users/me/following` returns accepted and pending relationships for restoring follow state.
- The readiness endpoint proves only that the Worker can execute a simple query against the bound D1 database.
- A successful Worker deployment and a successful readiness check do not mean the whole social network is production-ready.
- Keep the existing D1 database. Do not apply the unused PostgreSQL migration to it.

## Release gate

Keep the product in preview / controlled testing. Do not promote open registration or announce public launch until the release blockers above are addressed and the acceptance tests pass.
