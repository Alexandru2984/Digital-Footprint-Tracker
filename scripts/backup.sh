#!/usr/bin/env bash
#
# Daily PostgreSQL backup for swift-vapor.
#
# Reads DB credentials from /home/micu/swift+vapor/.env, pg_dumps the
# database, gzips the output, and writes a timestamped file to
# /home/micu/swift-vapor-backups/. Rotates so the last 7 dumps are kept.
#
# Triggered automatically by swift-vapor-backup.timer (02:00 UTC daily).
# Safe to run by hand for testing:
#   /home/micu/swift+vapor/scripts/backup.sh
#
# Exit codes:
#   0  — backup written, rotation complete
#   1  — fatal (env file missing, required var unset, pg_dump failure)
#

set -euo pipefail

ENV_FILE="/home/micu/swift+vapor/.env"
BACKUP_DIR="/home/micu/swift-vapor-backups"
RETENTION=7
LOCKFILE="${BACKUP_DIR}/.backup.lock"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Single-instance guard so overlapping cron + manual runs don't both write
# half-files at the same time. Non-blocking; if another run holds the lock,
# we exit 0 and let it finish.
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "backup: another run is in progress, skipping." >&2
    exit 0
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo "backup: env file $ENV_FILE not found." >&2
    exit 1
fi

# Pull only DATABASE_* into the environment. Sourcing the full .env would also
# export SMTP/API secrets, which we don't need and shouldn't leak into the
# pg_dump subprocess environment.
while IFS='=' read -r key value; do
    case "$key" in
        DATABASE_HOST|DATABASE_PORT|DATABASE_NAME|DATABASE_USERNAME|DATABASE_PASSWORD)
            # Strip surrounding quotes if any.
            value="${value%\"}"; value="${value#\"}"
            value="${value%\'}"; value="${value#\'}"
            export "$key=$value"
            ;;
    esac
done < <(grep -E '^DATABASE_[A-Z_]+=' "$ENV_FILE")

: "${DATABASE_HOST:?DATABASE_HOST not set in $ENV_FILE}"
: "${DATABASE_NAME:?DATABASE_NAME not set in $ENV_FILE}"
: "${DATABASE_USERNAME:?DATABASE_USERNAME not set in $ENV_FILE}"
: "${DATABASE_PASSWORD:?DATABASE_PASSWORD not set in $ENV_FILE}"
: "${DATABASE_PORT:=5432}"

STAMP="$(date -u +%Y-%m-%d_%H-%M-%S)"
OUT="${BACKUP_DIR}/footprint-${STAMP}.sql.gz"
TMP="${OUT}.partial"

echo "backup: dumping ${DATABASE_NAME}@${DATABASE_HOST}:${DATABASE_PORT} -> $OUT"

# Write to a .partial file first so a crash mid-dump never leaves a truncated
# file that looks like a complete backup during rotation. pg_dump uses pipefail
# semantics: any non-zero from either pg_dump or gzip aborts the script.
PGPASSWORD="$DATABASE_PASSWORD" pg_dump \
    --host="$DATABASE_HOST" \
    --port="$DATABASE_PORT" \
    --username="$DATABASE_USERNAME" \
    --dbname="$DATABASE_NAME" \
    --no-owner --no-privileges \
    --format=plain \
    | gzip --best > "$TMP"

mv "$TMP" "$OUT"
chmod 600 "$OUT"

# Rotation: keep the $RETENTION newest dumps, delete the rest.
mapfile -t old < <(
    ls -1t "$BACKUP_DIR"/footprint-*.sql.gz 2>/dev/null \
        | tail -n +$((RETENTION + 1))
)
for f in "${old[@]}"; do
    echo "backup: rotating out $f"
    rm -f "$f"
done

SIZE="$(stat -c %s "$OUT" 2>/dev/null || echo '?')"
echo "backup: complete (${SIZE} bytes, $(ls -1 "$BACKUP_DIR"/footprint-*.sql.gz | wc -l) kept)"
