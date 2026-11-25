#!/usr/bin/env bash
set -Eeuo pipefail

# Run from backend/ on the host with Docker Compose and age installed.
# Configure AGE_RECIPIENT with the public age recipient key.
: "${AGE_RECIPIENT:?Set AGE_RECIPIENT to the backup encryption recipient}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
mkdir -p "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$BACKUP_DIR/gomogie-$stamp.dump.age"
tmp="$final.tmp"

cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

docker compose exec -T db pg_dump -U gomogie -d gomogie -Fc \
  | age -r "$AGE_RECIPIENT" -o "$tmp"
test -s "$tmp"
mv "$tmp" "$final"

# Optional off-host R2 copy. Use a dedicated backup bucket/token, not the public media token.
if [[ -n "${BACKUP_R2_BUCKET:-}" ]]; then
  : "${BACKUP_R2_ENDPOINT:?Set BACKUP_R2_ENDPOINT to the R2 S3 endpoint}"
  : "${AWS_ACCESS_KEY_ID:?Set a dedicated backup R2 access key}"
  : "${AWS_SECRET_ACCESS_KEY:?Set a dedicated backup R2 secret}"
  command -v aws >/dev/null
  aws s3 cp "$final" "s3://$BACKUP_R2_BUCKET/db/$(basename "$final")" \
    --endpoint-url "$BACKUP_R2_ENDPOINT" --only-show-errors
  aws s3api head-object --bucket "$BACKUP_R2_BUCKET" --key "db/$(basename "$final")" \
    --endpoint-url "$BACKUP_R2_ENDPOINT" >/dev/null
fi

find "$BACKUP_DIR" -type f -name 'gomogie-*.dump.age' -mtime "+$RETENTION_DAYS" -delete
printf 'Encrypted backup created: %s\n' "$final"
