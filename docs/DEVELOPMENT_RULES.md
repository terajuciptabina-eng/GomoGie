# GomoGie — Development Rules

## Product identity and direction
- The official product name is **GomoGie** only. Do not append “Social” or another category suffix.
- Tagline: **Connect. Share. Discover.**
- Build GomoGie as an independent native social platform.
- Do not turn the core product into an aggregator of Facebook, YouTube, Instagram, X or other external social-network feeds.
- Do not make core product functionality dependent on third-party social-network APIs.

## Free-first commitment
- Core social participation must not require a subscription.
- Do not add hidden charges or surprise billing.
- Any optional paid service must be clearly described and priced before user commitment.
- Use transparent fair-use limits where infrastructure resources need protection.
- Do not promise unlimited storage, bandwidth, video processing or messaging.
- Consider advertising, sponsorship and optional services only with clear disclosure and privacy review; do not make monetisation a prerequisite for the prototype.

## Source control
- GitHub is the source of truth.
- Default branch is `main`.
- Work in small, reviewable commits.
- Do not rewrite history or force-push shared branches without explicit approval.
- Inspect current repository state before editing.
- Keep generated, temporary and secret files out of commits.

## Greenfield and evidence
- Build GomoGie from a clean foundation.
- Do not copy source code from other projects or third-party social platforms.
- Third-party libraries may be considered only after licence, security and maintenance review.
- Audit existing code and reproduce issues before changing behaviour.

## Engineering quality
- Fix root causes; do not stack speculative patches.
- Keep modules cohesive and boundaries explicit.
- Avoid unnecessary dependencies and premature microservices.
- Validate input and handle loading, empty, error and offline states.
- Use semantic HTML, keyboard support and accessible labels.
- Test responsive layouts on desktop, iPad Safari and iPhone.

## Demo-data integrity
- Synthetic users, posts, messages, metrics and activity must be labelled as demo data.
- Never imply prototype actions are persisted or delivered to real users.
- Never include real personal data, passwords, API keys or secrets in fixtures.

## Security and privacy
- Frontend visibility is not authorisation.
- All production access control must be enforced server-side.
- Minimise collection and retention of personal data.
- Review upload handling, rate limits, abuse controls and account deletion.
- Keep secrets in secure environment configuration.

## Changes and verification
Before implementation:
1. Inspect relevant source and current Git state.
2. Identify the root cause or explicit acceptance criteria.
3. State affected files and expected behaviour.

After implementation:
1. Run relevant automated checks.
2. Inspect the resulting diff.
3. Verify the target experience at relevant viewport sizes.
4. Report exactly what changed, what passed and what remains incomplete.

Do not claim a feature, test, deployment or security property is complete without evidence.
