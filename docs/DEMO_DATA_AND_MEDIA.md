# GomoGie — Demo Data and Media Rights

## Dataset disclosure

The prototype includes 1,000 synthetic account records and 120 synthetic post records. Every account, handle, bio, caption, timestamp and engagement count is generated for demonstration. These are not real people, members, creators, customers or measured platform activity.

Avatar URLs use a public placeholder-avatar service and are not evidence that the fictional account holder is a real person. They are prototype-only references and should be replaced with generated initials/illustrations or properly licensed and consented images before public production.

## Public stock media

The prototype references public stock image/video URLs, primarily from Pexels. Pexels states that its photos and videos can be used for free, including in commercial projects, subject to the Pexels licence and prohibited uses. Attribution is not required but is appreciated. The licence does not permit standalone redistribution of unmodified stock assets, and depicted people, brands, artwork or property may carry separate rights or consent requirements.

- Pexels licence: https://www.pexels.com/license/
- Pexels terms: https://www.pexels.com/terms-of-service/
- Pexels help — free use: https://help.pexels.com/hc/en-us/articles/360042295234-Are-the-photos-and-videos-on-Pexels-really-free

Unsplash is not selected as a bulk seed source for this project because its licence excludes compiling images to replicate a similar or competing service:
- Unsplash licence: https://unsplash.com/license

## Important implementation limits

- Media URLs in the prototype are remote references and have not all been individually verified for availability. A broken image/video must be replaced with a verified asset or shown with a graceful fallback.
- Do not scrape Pexels/Unsplash or bypass their official access mechanisms. For production automation, review official APIs and their current terms first.
- Keep provider/source-page metadata with each asset. Before public launch, conduct an asset-by-asset review and keep a licence/consent record.
- Do not imply a person, creator, photographer or brand depicted in stock media uses or endorses GomoGie.
- Synthetic profile identities must remain clearly labelled throughout the prototype.
- Do not treat the 1,000 fixture records as real user acquisition, active accounts or investor traction.

## Production replacement plan

1. Replace placeholder avatars with generated non-identifiable illustrations or consented user uploads.
2. Replace demo post media with licensed content or content uploaded by users who warrant they hold the necessary rights.
3. Implement upload consent, moderation, copyright/takedown and deletion workflows.
4. Use a managed media pipeline, storage and CDN; do not rely on third-party hotlinks for production reliability.
5. Review local privacy, copyright, personality/publicity and platform requirements before launch.
