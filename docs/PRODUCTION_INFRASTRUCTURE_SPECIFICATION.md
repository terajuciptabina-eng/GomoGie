# GomoGie — Production Infrastructure Specification

**Status:** Implementation foundation / controlled beta preparation  
**Date:** 25 November 2026  
**Source of truth:** GitHub `main`; implementation work is isolated in `feat/production-cloud-foundation`.

## 1. Executive decision

GomoGie remains an independent social network. Core participation is intended to remain free, with transparent fair-use limits for storage, upload, video processing and abuse prevention. RM0 is a target for a small controlled beta, not a guarantee of unlimited production capacity or service availability.

The current GitHub Pages app remains the static prototype. It must not be represented as a production backend. The new API is a separate service and is not yet wired into the browser UI.

## 2. Selected baseline

| Layer | Selection | Purpose |
|---|---|---|
| Static prototype | GitHub Pages | Existing frontend/demo only |
| API | Node.js 22 + Fastify | Modular monolith, REST API |
| Database | PostgreSQL 17 | Authoritative account/social/content data |
| Media | Cloudflare R2 Standard | Object storage; media is never stored in PostgreSQL |
| Media upload | Short-lived presigned PUT + server-side HEAD verification | Browser uploads directly to R2 |
| Public ingress | Cloudflare Tunnel | Avoid exposing the application port directly |
| Runtime | Docker Compose on Ubuntu ARM64 | Single-node controlled beta |
| CI | GitHub Actions | Syntax and dependency checks |
| Operations | PostgreSQL dump + encrypted off-host copy | Recovery baseline |

No separate microservices, Redis, Kubernetes, paid CDN or paid video service in this first deployment. A PostgreSQL-backed job table is the next step for asynchronous moderation and media processing; it is not yet implemented.

## 3. Free-tier constraints and cost guardrails

### Oracle Cloud Always Free

Oracle documents up to 1,500 OCPU-hours and 9,000 GB-hours monthly for Ampere A1, equivalent to 2 OCPUs and 12 GB RAM, in the tenancy's home region. Capacity is not guaranteed; an out-of-capacity response can prevent provisioning. Oracle also documents 200 GB combined block volume and up to 10 TB monthly outbound transfer for eligible resources. Recheck the Console's Always Free labels before creating anything.

This VM is suitable only for a modest controlled beta. It is a single point of failure, has no high availability, and may not have enough CPU for concurrent video encoding.

### Cloudflare R2

The published Standard free allowance is 10 GB-month storage, 1 million Class A operations and 10 million Class B operations per month; egress is free. Paid Standard storage is published at USD0.015/GB-month, with separate operation charges. Quotas and pricing can change; check the billing dashboard before enabling public uploads.

R2 free capacity is not enough for unlimited video. Enforce account and platform storage caps. Pause new uploads safely when the platform quota is reached; do not delete user media silently.

### Explicit exclusions from RM0

- Custom domain purchase/renewal.
- Paid email/SMS provider or SMS OTP.
- Unlimited video processing, live streaming and guaranteed uptime.
- Additional R2 storage/operations beyond free allowances.
- Professional moderation/support staffing.
- Legal, privacy, trademark and compliance advice.
- Any cloud resource outside an Always Free allowance.

Do not attach a payment card to paid resources or upgrade an account without the owner's explicit decision.

## 4. Service topology

```text
Browser / PWA
  | HTTPS
  v
Cloudflare DNS + Tunnel
  |
  v
Node.js Fastify API (Docker, private network)
  |                    |
  v                    v
PostgreSQL 17       Cloudflare R2
(private volume)    (presigned browser upload)
  |
  v
Encrypted backup -> off-host object storage
```

GitHub Pages remains separate until frontend API integration is explicitly scheduled. The browser must never receive database credentials, R2 secret keys or JWT signing secrets.

## 5. Implemented API foundation

Base path: `/v1`

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health/live` | No | Process liveness |
| `GET /health/ready` | No | Database readiness |
| `POST /v1/auth/register` | No | Create account and profile |
| `POST /v1/auth/login` | No | Verify password and issue short-lived JWT |
| `GET /v1/auth/me` | Bearer | Current account/profile |
| `GET /v1/feed` | No | Public feed with cursor |
| `POST /v1/posts` | Bearer | Create text post |
| `POST /v1/posts/:postId/reactions` | Bearer | Create/update reaction |
| `DELETE /v1/posts/:postId/reactions` | Bearer | Remove reaction |
| `POST /v1/posts/:postId/comments` | Bearer | Create comment |
| `POST /v1/users/:handle/follow` | Bearer | Follow account |
| `DELETE /v1/users/:handle/follow` | Bearer | Unfollow account |
| `POST /v1/media/uploads` | Bearer | Create short-lived R2 upload URL |
| `POST /v1/media/uploads/:uploadId/complete` | Bearer | Verify object metadata and register media |

This is an API foundation, not a complete social network. Messaging, communities, notification delivery, search, feed ranking, moderation operations, account recovery, email verification, privacy exports/deletion and admin console remain outstanding.

## 6. Security requirements before public beta

1. Replace all example secrets with randomly generated values held only in server-side environment configuration.
2. Configure exact production CORS origins; never use wildcard origins with credentials.
3. Keep PostgreSQL private; do not publish port 5432.
4. Expose the API only through the Cloudflare Tunnel; do not publish port 3000 publicly.
5. Require email verification and implement safe password reset before public registration.
6. Add MFA for administrators, role-based access control and audited admin actions.
7. Add CSRF protection if browser authentication moves to cookies. Current API uses Bearer JWT.
8. Add token revocation/rotation and refresh-session lifecycle before long-lived production sessions.
9. Add upload malware scanning, image decoding/re-encoding, video probing/transcoding, moderation and deletion workflow before user media becomes publicly visible.
10. Verify file size, content type and ownership on completion; do not trust client MIME claims alone.
11. Add per-user and platform storage quotas, rate limits, abuse detection and report queues.
12. Add privacy policy, terms, community standards, retention schedule and account deletion process.
13. Use TLS to the origin where required, pin container versions, patch dependencies and monitor security advisories.
14. Never commit secrets, real user data, database dumps or access tokens.

## 7. Media fair-use policy proposal

Initial beta limits are provisional and must be shown clearly in the product before uploads are enabled:

- Avatar: up to 5 MB.
- Image post: up to 10 MB per image.
- Video: up to 100 MB per upload for initial testing; duration/resolution policy is enforced after media processing is added.
- Platform storage: a hard cap set below the actual provider allowance, leaving room for thumbnails and operational overhead.
- No live streaming in the zero-cost phase.
- No unlimited upload or transcoding.
- Do not publish a video until scanning and processing are complete.

The API currently enforces 10 MB image and 100 MB video upload-intent limits by default. These are technical ceilings, not final user-facing policy.

## 8. Database and backup

- PostgreSQL is the source of truth.
- Use migrations; do not edit production schema manually.
- Keep database volume private and persistent.
- Create daily encrypted logical backups, retain a short rolling window and store at least one copy off the VM.
- Test restore to a separate database before beta.
- Backups must not be stored only on the same VM.
- Do not claim backup readiness until restore has been demonstrated.

## 9. Deployment procedure

1. Create an Oracle Cloud account and confirm an Ampere A1 instance is marked Always Free in the home region.
2. Provision Ubuntu ARM64 and secure SSH; disable password login after key access is confirmed.
3. Install Docker Engine and Compose plugin.
4. Create a Cloudflare Tunnel and map the API hostname to `http://api:3000` on the Docker network.
5. Copy `backend/.env.example` to a private `.env`; generate `JWT_SECRET` with a cryptographically secure random generator.
6. Set a strong `POSTGRES_PASSWORD` in the host environment.
7. Configure R2 bucket, scoped API token and public/custom media hostname. Keep R2 credentials server-side.
8. Start database and API with Compose; verify `/health/live` and `/health/ready`.
9. Test registration, login, feed, post, reaction, comment and upload using non-production demo accounts.
10. Configure backups, restore test, monitoring, alerts and abuse controls.
11. Only then connect the frontend and invite a small closed beta.

Never run provisioning or paid cloud actions without the account owner's explicit approval.

## 10. Rollout gates

| Gate | Required evidence | Status |
|---|---|---|
| Repository foundation | API code, schema, container files, docs | In progress on feature branch |
| Local runtime | Docker Compose starts and DB health is ready | Not run in this environment |
| API verification | Automated integration tests pass | Not run |
| Cloud provisioning | Always Free VM exists and is reachable | Not provisioned |
| R2 integration | Upload and readback tested | Credentials not supplied |
| Security | Email verification, reset, moderation, scanning, restore test | Not complete |
| Frontend integration | Prototype uses real API, no fake local persistence claims | Not started |
| Closed beta | Operational checklist and user-facing policy approved | Not ready |

**Release rule:** do not announce production-ready or open public registration until every mandatory public-beta gate is verified.
