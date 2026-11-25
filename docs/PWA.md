# GomoGie Progressive Web App

## Published PWA foundation

GomoGie is served from GitHub Pages and can be added to a device Home Screen. The current PWA layer includes:

- A web app manifest with standalone display mode and a stable project-site scope.
- Dedicated PNG icons for iOS Home Screen and Android/browser installation.
- A service worker that checks the network first for the app shell and static assets.
- Versioned cache cleanup when a new service-worker version activates.
- Cached demo account and post fixtures, allowing the prototype feed to load from the last successful cache when offline.
- A navigation fallback to the cached app entry point when the network is unavailable.
- Update checks when the app opens, regains focus or returns to the foreground.

## Install on iPhone or iPad

1. Open the published GomoGie URL in **Safari**.
2. Wait for the page and demo content to finish loading while online. This allows the service worker and offline fixtures to be cached.
3. Tap **Share** in Safari.
4. Choose **Add to Home Screen**.
5. Keep **Open as Web App** enabled if that option is shown, then tap **Add**.
6. Launch GomoGie from its Home Screen icon.

For an existing Home Screen installation, open the same GomoGie URL once in Safari while online, allow it to finish loading, then reopen the Home Screen app. The service worker can then control that site scope and check for later releases.

## Install on Android

Open GomoGie in a supported browser such as Chrome, use the browser's **Install app** or **Add to Home screen** option, and follow the browser prompt.

## Update behaviour

The service worker checks for a newer deployment on page load and when the app returns to the foreground. A newly activated worker takes control of the site. The page reloads once when an already-controlled page receives a new controller so it can use the latest deployed app shell.

Updates require an internet connection. If an update is not appearing, close the app, open GomoGie in Safari/Chrome while online, reload once, and then reopen the installed app.

## Offline behaviour and limits

When a device has previously loaded GomoGie successfully, the app shell and the last cached demo JSON fixtures can be served offline. The prototype can therefore reopen with its last cached sample feed.

Offline mode does **not** provide a production social backend. It does not enable real account sign-in, cross-device synchronisation, server-side posting, live messaging, upload processing, or live video. External stock images and videos may still require an internet connection because they are hosted outside GomoGie's own site.

## Testing checklist

- [ ] Open the site in Safari on iPhone and confirm the Home Screen icon uses the GomoGie mark.
- [ ] Add to Home Screen and confirm the app opens in standalone mode.
- [ ] Reload once online and confirm the current demo feed appears.
- [ ] Open the installed app after a new deployment and confirm it updates.
- [ ] Load the app and fixtures once, enable Airplane Mode, then reopen and confirm the cached feed appears.
- [ ] Disable Airplane Mode and confirm refresh returns to the current fixtures.
- [ ] Repeat layout and navigation checks on iPad Safari and desktop browsers.

Device-specific checks must be completed on actual devices; GitHub Actions validation alone cannot certify iOS Home Screen behaviour.
