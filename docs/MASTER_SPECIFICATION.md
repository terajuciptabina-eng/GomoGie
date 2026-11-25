# GomoGie — Master Product Specification

## 1. Product vision

Build GomoGie as an independent, welcoming social platform where people can share moments, follow public conversations, watch video, join communities and communicate in one coherent experience.

**Official product name:** GomoGie  
**Tagline:** Connect. Share. Discover.

The product name is GomoGie only. Do not append “Social” or another category suffix to the official brand name.

GomoGie is its own social network, not a dashboard that aggregates feeds from Facebook, YouTube, Instagram, X or other external platforms. Its core product experience must be built around native GomoGie accounts, content, relationships and communities.

## 2. Free-first product commitment

- Core participation is free: account/profile, publishing within fair-use limits, feed browsing, following, reactions, comments, communities and basic messaging.
- No mandatory subscription or paywall for core social participation.
- No hidden charges. Any optional paid service, purchase or usage-based charge must be clearly disclosed before the user commits.
- Free access does not imply unlimited storage, bandwidth, video processing or abuse-prone usage. Establish transparent fair-use limits that protect service quality and operating sustainability.
- Monetisation should not undermine trust or make basic participation pay-to-win.
- Preferred potential revenue sources include clearly labelled advertising, sponsorships and genuinely optional creator/business services. These are future decisions, not implemented features.
- Do not promise that GomoGie will have zero operating costs. Hosting, media storage, delivery, moderation, security and support require funding.

## 3. Product principles

- Independent platform: native GomoGie identity, social graph and content.
- People-first: meaningful participation over manipulative engagement.
- Clear controls: understandable privacy, audience and interaction settings.
- Creator-respecting: transparent publishing and analytics tools.
- Safe by design: reporting, blocking, moderation and appeals.
- Mobile-first without neglecting desktop and tablet.
- International-ready: avoid hard-coding Malaysia-specific assumptions into core logic.
- Sustainable free access: manage infrastructure costs responsibly and transparently.

## 4. Core product areas

### Feed
A personalised and following feed containing text, images, links and polls. Support reactions, comments, replies, sharing, reposts and quote posts.

### Pulse
A public conversation surface for short updates, hashtags, topics and emerging discussions. Trending must be explainable and protected against manipulation.

### Watch
A video discovery and viewing experience for short and long-form content, creator channels, playlists and subscriptions/follows. Production video requires a media pipeline, storage and delivery strategy.

### Communities
Public, private or approval-based communities with membership roles, posts, rules, reporting and moderation tools.

### Connect
One-to-one and group conversations, message requests, attachments and notification controls. Real-time delivery requires backend infrastructure.

### Studio
Creator profile/channel management, content publishing, moderation status, audience insights and future optional monetisation controls.

## 5. Account types and roles

- Visitor: view publicly available pages and content according to access rules.
- Member: manage profile, publish and interact within permissions.
- Creator: access creator/channel tools.
- Business account: represent an organisation or brand.
- Moderator: review reports and enforce community rules within assigned scope.
- Administrator: platform operations and moderation.
- Super administrator: highest-level system configuration and access governance.

Role permissions must be enforced by the backend, not merely hidden in the frontend.

## 6. MVP scope

The first usable prototype should demonstrate:
- Responsive application shell and navigation.
- Synthetic demo profiles and content, clearly labelled as demo data.
- Feed cards for text, image, video preview and poll examples.
- Post composer interaction.
- Reactions, comments/replies and repost interactions in local prototype state.
- Pulse topic list and hashtag discovery.
- Watch discovery cards and a channel profile mock.
- Community directory and community detail mock.
- Messaging inbox and conversation mock.
- Search, notifications and profile views.
- Accessible states, empty states and mobile navigation.
- Clear indication that prototype data and interactions are simulated.

Prototype interactions do not imply production persistence, real authentication, real messaging or real media hosting.

## 7. Explicitly out of scope for the first prototype

- External social-network feed aggregation or cross-platform account management.
- Production user registration and authentication.
- Real-time chat delivery.
- Production image/video uploads or transcoding.
- Payment processing, subscriptions or advertising.
- Algorithmic ranking presented as production-ready.
- Public launch or claims of security certification.

## 8. Non-functional requirements

- Responsive layouts for phone, tablet and desktop.
- Keyboard accessibility and visible focus states.
- Semantic HTML and screen-reader labels.
- Performance-conscious media loading.
- Clear loading, error, empty and offline states.
- Secure-by-design backend plan before real user data is accepted.
- Data minimisation, consent and retention policies.
- Moderation, abuse reporting and account recovery workflows.
- Cost monitoring for storage, bandwidth, media processing and messaging.

## 9. Success criteria for prototype

A first prototype is acceptable when the principal navigation areas are coherent, core interactions can be demonstrated with synthetic data, layouts work at mobile/tablet/desktop widths, and no interface implies that demo actions have been persisted to a real service.

## 10. Open product decisions

- Launch jurisdictions and age policy.
- Final logo system, colour tokens and typography.
- Public/private account and post audience rules.
- Content policy and moderation escalation.
- Backend, database, object storage, search and realtime provider selection.
- Fair-use limits and cost-control thresholds.
- Sustainable monetisation approach that preserves free core access.
- Domain and trademark clearance.


## 11. Combined product inspirations and GomoGie capabilities

GomoGie combines product ideas from five categories of social platforms while maintaining its own brand, interface, data model and implementation:

- Facebook-inspired social networking: friend/follower graph, feed, groups/communities, pages and events.
- Twitter/X-inspired public conversation: short posts, replies, reposts, quote posts, hashtags and trending topics.
- Instagram-inspired visual sharing: photo posts, carousels, stories, creator profiles, saves and short-form video.
- YouTube-inspired video platform: long-form video, channels, subscriptions/follows, playlists and live video.
- TikTok-inspired discovery: vertical full-screen short-video feed, For You recommendations, Following feed, creator discovery and future remix/reply formats.

These are functional inspirations, not permission to copy another platform's protected branding, source code, exact UI, trademarks or proprietary assets. GomoGie must develop its own interaction design and identity.

## 12. Synthetic prototype population and public media

- Prototype dataset target: 1,000 synthetic accounts and 120 synthetic posts.
- All demo identities, handles, bios, counts, captions and activity are fictional and must carry clear demo labeling.
- Synthetic accounts are not real registered users and must never be used to imply real traction, active membership or endorsements.
- Public stock images/videos may be used for prototype media only after checking the relevant asset licence and third-party rights.
- Store media source/provider and source-page references in the dataset. Prefer official provider embeds or permitted hosted URLs; do not scrape or mirror media.
- Public profile-photo placeholders are for prototype display only. Replace or re-license them before production.
- Never imply a person shown in stock media is a GomoGie user, employee, creator or endorser.
- Production media must be user-uploaded with rights warranties, or sourced under a documented licence and consent process.

## 13. Prototype acceptance criteria

- The static prototype loads 1,000 synthetic account records and 120 synthetic post records from versioned JSON.
- Navigation demonstrates Home, Pulse, Watch, Communities, Connect and Studio.
- Home displays story-style profile circles, a post composer and a mixed feed.
- Watch distinguishes For You and Following as separate product modes; recommendation logic in the prototype is illustrative only.
- Like, follow, comment, share and composer interactions are explicitly simulated and do not persist to a backend.
- Media failures must degrade gracefully to thumbnails or source links.
- All prototype pages must identify synthetic data and avoid implying a production service is live.

