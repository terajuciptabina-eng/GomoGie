# GomoGie Developer Console — first-owner setup

The Developer Console is protected by server-side authentication and the `developer_admins` D1 table. A hidden URL or frontend flag does not grant access.

## One-time Cloudflare setup

1. Generate a strong random secret locally (at least 32 characters). Do not commit it or paste it into chat.
2. From `workers/api`, store it as a Worker secret:

   ```sh
   npx wrangler secret put DEVELOPER_BOOTSTRAP_SECRET
   ```

3. Deploy the API Worker after the secret is configured.
4. Sign in to GomoGie using the account that should own the platform.
5. Open **Developer** from the navigation, enter the one-time secret, and select **Activate owner console**.

The API only permits bootstrap when the developer-admin table is empty. The first successful account receives `super_admin`. Once an owner exists, the bootstrap endpoint permanently rejects further bootstrap attempts. Keep the secret private; rotate/remove it after setup with Cloudflare Worker secret management.

## Current console scope

- Server-verified developer role and capability response.
- First-owner bootstrap protected by a Cloudflare Worker secret.
- Overview metrics: registered users, active users, posts, Pulse articles and developer administrators.
- Recent developer audit activity.
- D1 schema for developer roles and immutable-style audit history.

## Security notes

- Do not add administrator status to browser local storage or trust client-supplied role names.
- All privileged API routes must check `developer_admins` after authenticating the user.
- Future account, content, configuration and feature-flag actions must create an audit record and enforce role capabilities server-side.
- Never expose JWT secrets, Worker secrets, private message content or raw credentials in the console.
