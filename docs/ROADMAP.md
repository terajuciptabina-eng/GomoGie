# GomoGie — Roadmap

## Phase 0 — Foundation
- [x] Create public GitHub repository.
- [x] Commit initial product and technical foundation documents.
- [ ] Establish source structure and contribution rules.
- [ ] Add automated checks.
- [ ] Establish visual identity and design tokens.
- [x] Confirm official product name: GomoGie.
- [x] Set direction: independent native social platform, not external social-feed aggregator.
- [x] Set principle: core user experience is free-first, with transparent fair-use limits.

## Phase 1 — Interactive prototype
- [ ] Responsive app shell and navigation.
- [ ] Home feed and post composer.
- [ ] Pulse topics and discovery.
- [ ] Watch video discovery mock.
- [ ] Communities directory and detail.
- [ ] Messaging inbox and conversation mock.
- [ ] Notifications, search and profile mock.
- [x] Synthetic fixture provenance retained internally; public interface uses one site-wide sample-content notice instead of per-account labels.
- [ ] Test desktop, iPad Safari and iPhone layouts.
- [ ] Publish prototype through GitHub Pages.

## Phase 2 — Production architecture
- [ ] Select backend, database and object storage after requirements and cost review.
- [ ] Define authentication, sessions and account recovery.
- [ ] Define API contracts and authorisation matrix.
- [ ] Implement core account, profile and social graph services.
- [ ] Implement content, feed and interaction persistence.
- [ ] Add media storage, scanning and processing pipeline.
- [ ] Define transparent fair-use quotas for media, messaging and other resource-intensive features.
- [ ] Add cost monitoring, budget alerts and abuse controls.
- [ ] Add moderation/reporting and audit controls.
- [ ] Add observability, backups and recovery tests.

## Phase 3 — Controlled beta
- [ ] Messaging and realtime delivery.
- [ ] Communities and moderation workflows.
- [ ] Search and discovery.
- [ ] Privacy, security and performance testing.
- [ ] Validate free-tier operating costs under realistic usage.
- [ ] Closed beta with feedback and incident procedures.

## Phase 4 — Public launch readiness
- [ ] Legal, privacy, terms and community standards review.
- [ ] Trademark/domain clearance.
- [ ] Accessibility and security assessment.
- [ ] Operational support and moderation coverage.
- [ ] Launch transparent advertising/sponsorship or optional services only if sustainable and appropriate.
- [ ] Preserve free access to core social participation.

Roadmap completion must reflect verified implementation, not planned work.


## Phase 1A — Synthetic dataset and prototype shell
- [x] Create 1,000 internally tagged synthetic account fixtures.
- [x] Create 120 internally tagged synthetic post fixtures with public-media references.
- [x] Add a responsive static prototype shell and six navigation areas.
- [ ] Verify each public image/video URL and source page in a browser.
- [ ] Replace any unavailable media links and record asset-level source details.
- [ ] Test all navigation and interactions on desktop, iPad Safari and iPhone.
- [ ] Publish to GitHub Pages and verify the deployed URL.
- [x] Review synthetic-data disclosure and ensure fixture counts are not used as traction metrics.

## Phase 1B — Feature-depth prototype
- [ ] Add stories viewer and create-story simulation.
- [ ] Add Instagram-style photo carousel and profile grid.
- [ ] Add vertical Watch player with distinct For You and Following tabs.
- [ ] Add video channel pages, long-form player and playlists.
- [ ] Add post replies, quote reposts, polls and hashtag search.
- [ ] Add community membership, roles and events mock flows.
- [ ] Add messaging conversation UI with clear simulation label.
- [ ] Add profile settings, privacy controls and report/block mock flows.



## Profile experience prototype
- [x] Profile header with cover photo and avatar.
- [x] Display name, handle, bio, location, website and join year.
- [x] Posts, followers and following summary.
- [x] Profile post grid with image and video tiles.
- [x] Posts, Videos and Saved tabs.
- [x] Edit profile demo form with local avatar/cover preview.
- [x] Open a profile from a feed post or the top-right profile avatar.
- [x] Discover profiles through search and profile directory.
- [ ] Persist profile edits, follows and saved posts using a secure backend after authentication is implemented.
- [ ] Implement real upload, image processing, privacy settings, block/report and follow relationship APIs.

## Production integration progress — 25 November 2026

- [x] Cloudflare Worker authentication: login, `/v1/auth/me` verification and remembered-session renewal; manually verified by the project owner across page refresh and a full browser close/reopen.
- [x] Authenticated Following feed API and Home feed tabs: own posts plus posts from accepted follow relationships; pending private-account requests are excluded.
- [ ] Verify Following feed with two real test accounts, including public follow, private pending follow, unfollow and own private post cases.
- [ ] Complete server-side privacy/visibility audit across feed, profile, post, comment, media, search and notifications routes.
- [ ] Complete rate limiting, account recovery, email verification and session revocation before opening registration broadly.
