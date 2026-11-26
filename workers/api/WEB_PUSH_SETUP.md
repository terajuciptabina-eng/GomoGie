## Web Push notifications

GomoGie supports browser push notifications for signed-in accounts. The feature requires one-time Cloudflare Worker secrets and a D1 migration.

### 1. Generate VAPID credentials (once)

From `workers/api`, run the command with a real, monitored contact email address:

```sh
node scripts/generate-vapid.mjs your-monitored-email@example.com
```

The helper refuses to generate keys if no valid contact email is supplied. It prints a public key, a private JWK, and the `mailto:` subject. Generate the pair once and keep the private JWK secret.

Keep the private JWK secret. Never commit it or share it publicly. Use a real monitored contact address for `VAPID_SUBJECT`.

### 2. Configure Worker secrets

From `workers/api`, set the values printed by the script:

```sh
npx wrangler secret put VAPID_PUBLIC_KEY
npx wrangler secret put VAPID_PRIVATE_JWK
npx wrangler secret put VAPID_SUBJECT
```

Paste each corresponding value when Wrangler prompts. Use the same key pair for every deployment of this Worker.

### 3. Apply the D1 migration and deploy

```sh
npx wrangler d1 migrations apply gomogie-db --remote
npx wrangler deploy
```

### 4. Enable on a device

Sign in to GomoGie, open Notifications, choose **Enable push**, and allow browser notifications. On iPhone/iPad, install GomoGie to the Home Screen and open it from there before enabling push. Push support depends on the iOS/iPadOS version and permission state.

The app stores one subscription per browser/device and account. Expired push endpoints are removed automatically. In-app notifications remain available even if push permission is denied.
