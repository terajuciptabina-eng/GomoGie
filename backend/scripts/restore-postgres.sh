#!/usr/bin/env bash
set -Eeuo pipefail

# Restore an encrypted custom-format dump into an EMPTY target database.
# Take the application offline and verify the target database before running.
: "${BACKUP_FILE:?Set BACKUP_FILE to a .dump.age file}"
: "${AGE_IDENTITY:?Set AGE_IDENTITY to the private age identity file}"
test -s "$BACKUP_FILE"
test -s "$AGE_IDENTITY"

age -d -i "$AGE_IDENTITY" "$BACKUP_FILE" \
  | docker compose exec -T db pg_restore --no-owner --no-privileges -U gomogie -d gomogie -

printf 'Restore stream completed. Run integrity checks and application smoke tests before reopening traffic.\n'
