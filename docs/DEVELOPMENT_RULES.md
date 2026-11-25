# GomoGie — Development Rules

## Source control
- GitHub is the source of truth.
- Default branch is `main`.
- Work in small, reviewable commits.
- Do not rewrite history or force-push shared branches without explicit approval.
- Inspect current repository state before editing.
- Keep generated, temporary and secret files out of commits.

## Greenfield and evidence
- Build GomoGie from a clean foundation.
- Do not copy source code from WoHoo, other projects or third-party social platforms.
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
