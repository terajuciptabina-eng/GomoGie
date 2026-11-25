# GomoGie — Architecture

## 1. Architecture strategy

Build GomoGie as an independent social network with native identity, social graph, content, media, communities and messaging. Begin with a static, responsive frontend prototype hosted through GitHub Pages. Keep production service boundaries explicit so the prototype can later connect to real backend APIs without pretending browser-local state is a backend.

The core experience must not depend on external social-network APIs or external account aggregation.

## 2. Initial prototype

- Static HTML, CSS and JavaScript unless a later evidence-based decision justifies a framework.
- Modular source structure with clear separation of UI, mock data and interaction state.
- Synthetic data stored in version-controlled fixtures.
- Local state only for demonstration interactions.
- No secrets, credentials or personal user data in the repository.
- GitHub Actions for validation and GitHub Pages deployment.
- No external social-account OAuth flow in the MVP prototype.

## 3. Proposed production logical components

1. Web client: responsive application, accessibility and client-side routing.
2. API gateway/backend: authentication, authorisation, validation, rate limiting and business rules.
3. Identity service: account lifecycle, sessions, recovery and optional MFA.
4. Social graph: follows, blocks, mutes and relationship queries.
5. Content service: posts, comments, reactions, feeds and visibility rules.
6. Media service: upload authorisation, object storage, scanning, transcoding and delivery.
7. Messaging service: conversations, message permissions and realtime delivery.
8. Search/discovery: indexing, query and trend computation.
9. Notification service: in-app and optional push/email delivery.
10. Trust and safety: reports, moderation queues, enforcement and appeals.
11. Analytics: privacy-aware product and creator metrics.
12. Admin console: least-privilege operations and audit trails.

These are logical boundaries, not a commitment to deploy separate microservices. Start with a well-structured backend and split components only when scale or team ownership justifies it.

## 4. Free-first sustainability and cost controls

The product should offer core participation without mandatory user subscriptions. Architecture and product limits must nevertheless account for real infrastructure costs.

- Track storage, bandwidth, video transcoding, realtime connections, notifications and moderation costs.
- Apply transparent fair-use quotas and upload limits where necessary.
- Use image resizing, video transcoding profiles, caching and CDN delivery to control media costs.
- Prevent spam, automated abuse and resource exhaustion with rate limits and risk controls.
- Design optional monetisation separately from core access; advertising or sponsorship must be clearly labelled and privacy-conscious.
- Never introduce a hidden charge or silently convert a free feature into a paid feature.
- Do not claim unlimited free media storage or unlimited bandwidth.

## 5. Data and infrastructure principles

- Relational database as the authoritative store for core entities and relationships.
- Object storage/CDN for uploaded media; never store large media blobs in relational rows.
- Queue/event mechanism for notifications, media processing and asynchronous tasks.
- Search index derived from authoritative content records.
- Explicit backup, restore, retention and deletion procedures.
- Region, privacy and data-residency choices must be reviewed before launch.
- Establish budget alerts and service-level cost monitoring before opening uploads to the public.

## 6. Security boundaries

- Enforce authorisation server-side for every private resource and mutation.
- Use secure session/token lifecycle and protect against CSRF/XSS/IDOR.
- Validate and rate-limit user-generated content and messaging endpoints.
- Scan uploaded files and constrain media formats and sizes.
- Keep secrets in deployment secret stores, never in source or client bundles.
- Log privileged actions without unnecessarily logging message bodies or sensitive data.
- Define incident response, backup recovery and account deletion workflows.

## 7. Deployment

Prototype:
- GitHub repository as source of truth.
- GitHub Actions validates and publishes the static frontend to GitHub Pages.
- Public URL target: https://terajuciptabina-eng.github.io/GomoGie/

Production:
- Requires a separately selected backend and infrastructure.
- GitHub Pages must not be treated as a dynamic application server or database.
- Production deployment architecture is an open decision and must be reviewed before implementation.

## 8. Architecture decision records

Record consequential decisions in `docs/decisions/` with context, options, decision, consequences and date. Do not silently change foundational architecture.
