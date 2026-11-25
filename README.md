# GomoGie

**Connect. Share. Discover.**

GomoGie is an independent social platform where people can share moments, follow conversations, watch videos, join communities and communicate in one place.

## Product direction

GomoGie is its own social network. It is not an aggregator for Facebook, YouTube, Instagram, X or other external platforms, and its core experience must not depend on their APIs.

**Free-first commitment:** core social features are intended to remain free for users. The product must be designed for sustainable operation without mandatory subscriptions or hidden charges. This does not mean infrastructure has zero cost or that storage and usage can be unlimited; fair-use limits and any optional paid services must be transparent.

## Project status

- Repository: public, GitHub-first
- Default branch: `main`
- Current phase: product specification and foundation
- Initial delivery: responsive interactive prototype using clearly labelled synthetic demo data
- Hosting target: GitHub Pages for the static frontend prototype

> GitHub Pages is static hosting. It is not the backend for production authentication, persistent user data, messaging, uploads or video processing. Those capabilities require separately designed backend services.

## Core product areas

1. **Feed** — text, image, link and poll posts; reactions, comments, sharing and reposts.
2. **Pulse** — short updates, topics, hashtags and discovery.
3. **Watch** — short and long videos, creator channels and playlists.
4. **Communities** — public/private communities, membership and moderation.
5. **Connect** — direct and group messaging.
6. **Studio** — creator tools, publishing workflow and analytics.

## Documentation

- [Master specification](docs/MASTER_SPECIFICATION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Data model](docs/DATA_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Development rules](docs/DEVELOPMENT_RULES.md)
- [Brand identity](docs/BRAND_IDENTITY.md)

## Guiding principles

- Build GomoGie as an independent product from a clean foundation.
- Keep core user features free; do not require a subscription to participate.
- Prefer sustainable, transparent monetisation such as clearly labelled advertising, sponsorships or optional services.
- Do not make the product dependent on third-party social-network APIs.
- Audit before implementation and preserve evidence of decisions.
- Fix root causes rather than layering patches.
- Design responsive experiences for desktop, iPad Safari and iPhone.
- Treat privacy, safety, accessibility and moderation as core requirements.
- Never present synthetic demo content as real users or activity.

## Brand note

The product name is **GomoGie** only. Do not append a product-category suffix to the official name. Trademark, company-name, domain and handle clearance remain separate tasks and have not been certified by this repository setup.
