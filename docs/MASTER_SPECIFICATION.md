# GomoGie — Master Product Specification

## 1. Product vision

Create a welcoming, modern social platform where people can share moments, follow public conversations, watch video, join communities and communicate without needing separate disconnected experiences.

**Brand:** GomoGie  
**Product descriptor:** GomoGie Social  
**Tagline:** Connect. Share. Discover.

GomoGie should establish its own visual language, interaction patterns and product identity. It may learn from familiar social-product conventions but must not copy protected branding, layouts or source code.

## 2. Product principles

- People-first: useful connections and meaningful participation over engagement manipulation.
- Unified content: one coherent publishing model across supported post types.
- Clear controls: privacy, audience and interaction settings are understandable.
- Creator-respecting: transparent publishing and analytics tools.
- Safe by design: reporting, blocking, moderation and appeals are planned from the start.
- Mobile-first without neglecting desktop and tablet.
- International-ready: avoid hard-coding Malaysia-specific assumptions into core product logic.

## 3. Core product areas

### Feed
A personalised and following feed containing text, images, links and polls. Support reactions, comments, replies, sharing, reposts and quote posts.

### Pulse
A fast public conversation surface for short updates, hashtags, topics and emerging discussions. Trending must be explainable and protected against obvious manipulation.

### Watch
A video discovery and viewing experience for short and long-form content, creator channels, playlists and subscriptions. Production video requires a media pipeline and storage strategy.

### Communities
Public, private or approval-based communities with membership roles, posts, rules, reporting and moderation tools.

### Connect
One-to-one and group conversations, message requests, attachments and notification controls. Real-time delivery requires backend infrastructure.

### Studio
Creator profile/channel management, content publishing, moderation status, audience insights and future monetisation controls.

## 4. Account types and roles

- Visitor: view publicly available pages and content according to access rules.
- Member: manage profile, publish and interact within permissions.
- Creator: access creator/channel tools.
- Business account: represent an organisation or brand.
- Moderator: review reports and enforce community rules within assigned scope.
- Administrator: platform operations and moderation.
- Super administrator: highest-level system configuration and access governance.

Role permissions must be enforced by the backend, not merely hidden in the frontend.

## 5. MVP scope

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

Prototype interactions do not imply production persistence, real authentication, real messaging or real media hosting.

## 6. Explicitly out of scope for the first prototype

- Production user registration and authentication.
- Real-time chat delivery.
- Production image/video uploads or transcoding.
- Payment processing, subscriptions or advertising.
- Algorithmic ranking presented as production-ready.
- Public launch or claims of security certification.

## 7. Non-functional requirements

- Responsive layouts for phone, tablet and desktop.
- Keyboard accessibility and visible focus states.
- Semantic HTML and screen-reader labels.
- Performance-conscious media loading.
- Clear loading, error, empty and offline states.
- Secure-by-design backend plan before real user data is accepted.
- Data minimisation, consent and retention policies.
- Moderation, abuse reporting and account recovery workflows.

## 8. Success criteria for prototype

A first prototype is acceptable when the principal navigation areas are coherent, core interactions can be demonstrated with synthetic data, layouts work at mobile/tablet/desktop widths, and no interface implies that demo actions have been persisted to a real service.

## 9. Open product decisions

- Launch jurisdictions and age policy.
- Final logo system, colour tokens and typography.
- Public/private account and post audience rules.
- Content policy and moderation escalation.
- Backend, database, object storage, search and realtime provider selection.
- Domain and trademark clearance.
- Monetisation model and launch sequencing.
