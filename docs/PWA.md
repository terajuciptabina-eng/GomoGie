# GomoGie PWA, connectivity and offline behaviour

## Product behaviour
GomoGie is an online social network. Internet access is required for publishing, messaging, reactions that reach other members, fresh feeds, notifications, uploads and streaming.

The installed web app remains available from the iPhone/iPad Home Screen. Its shell is refreshed network-first and a previously loaded app shell is used only as a fallback when the network is unavailable.

## Offline experience in the static prototype
- A clear offline notice appears when the device loses connectivity.
- The latest successfully loaded demo account and post fixtures are saved in IndexedDB and can be shown again offline.
- The Service Worker caches demo JSON using a normalized URL, so cache-busting refresh parameters do not prevent offline fallback.
- A text post composed in the prototype is saved on that device and displayed locally as pending.
- Pending posts are not published or synchronized. This GitHub Pages prototype has no production account service or social backend.

## Production requirements
Before offline actions can synchronize like a mature social network, GomoGie needs authenticated accounts, durable posts/comments/reactions, idempotent write endpoints, conflict handling, media storage/CDN and a server-confirmed sync API. IndexedDB can then hold an outbox and retry only actions accepted by the server. Device online status alone does not prove that the backend is reachable.

## Cache policy
- App shell and static assets: network-first with cached fallback.
- Demo fixtures: network-first with cache fallback keyed independently of cache-busting query parameters.
- User-generated production media: governed by explicit storage limits and privacy policy; do not cache all video automatically.
