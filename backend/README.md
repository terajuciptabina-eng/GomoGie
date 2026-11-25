# GomoGie API

Node.js 22 / Fastify API foundation for controlled beta preparation.

## Local setup

1. Copy `.env.example` to `.env`.
2. Set a local-only `JWT_SECRET` with at least 32 characters.
3. Start from this directory:

```sh
docker compose up --build
```

4. Check:
   - `http://127.0.0.1:3000/health/live`
   - `http://127.0.0.1:3000/health/ready`

PostgreSQL is private to the Compose network. The API is bound to loopback for local development. The database migration runs automatically only when the named volume is first initialized. For a reset of disposable local data only, run `docker compose down -v` and start again.

## Production

Do not expose PostgreSQL or the API port publicly. Use the optional `production` Cloudflare Tunnel profile after setting `CLOUDFLARE_TUNNEL_TOKEN` on the host and configuring the tunnel's public hostname service to `http://api:3000`.

Configure R2 credentials and a dedicated bucket before enabling media uploads. Never put secrets in Git.

## Important beta warning

Registration currently creates an unverified account and returns a short-lived bearer token for integration testing. Email verification, password reset, session revocation, admin MFA, malware scanning, video processing, moderation and account deletion are not implemented. Do not expose this API to public users until those controls are complete.

See [Production Infrastructure Specification](../docs/PRODUCTION_INFRASTRUCTURE_SPECIFICATION.md).


## Backup and restore

Install `age` on the host. Generate an encryption identity with `age-keygen`; keep the private key offline and set the public `AGE_RECIPIENT` on the server.

From `backend/` with the stack running:

```sh
AGE_RECIPIENT='age1...' bash scripts/backup-postgres.sh
```

Optional off-host R2 upload requires a dedicated private backup bucket and separate scoped access key:

```sh
AGE_RECIPIENT='age1...' \
BACKUP_R2_BUCKET='gomogie-private-backups' \
BACKUP_R2_ENDPOINT='https://ACCOUNT_ID.r2.cloudflarestorage.com' \
AWS_ACCESS_KEY_ID='...' AWS_SECRET_ACCESS_KEY='...' \
bash scripts/backup-postgres.sh
```

Restore only into an empty target database after stopping application traffic:

```sh
BACKUP_FILE='./backups/gomogie-....dump.age' \
AGE_IDENTITY='/secure/offline/path/age-identity.txt' \
bash scripts/restore-postgres.sh
```

The scripts are committed but a real restore test has not yet been run. Configure R2 lifecycle expiry for the backup bucket separately.
