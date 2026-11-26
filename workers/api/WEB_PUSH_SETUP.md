## Web Push notifications

GomoGie supports browser push notifications for signed-in accounts. The D1 subscription migration and Cloudflare Worker deployment are handled by the GitHub Actions workflow.

### One-time deployment setup

The repository workflow uses the two existing GitHub Actions repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

No VAPID secrets need to be added manually. During a manually triggered deployment, the workflow checks the live Worker public-key endpoint. If a valid VAPID key pair is already configured, it preserves that pair so existing browser subscriptions continue working. If Push is not configured, it generates a P-256 VAPID pair in the ephemeral GitHub Actions runner and sends the values directly to Cloudflare Worker secrets. The private JWK is never printed or committed to the repository.

The VAPID contact subject is `mailto:terajuciptabina@gmail.com`.

### Enable on a device

Sign in to GomoGie, open Notifications, choose **Enable push**, and allow browser notifications. On iPhone/iPad, install GomoGie to the Home Screen and open it from there before enabling push. Push support depends on the iOS/iPadOS version and permission state.

The app stores one subscription per browser/device and account. Expired push endpoints are removed automatically. In-app notifications remain available even if push permission is denied.
