#!/usr/bin/env bash
#
# Daily PostgreSQL backup for swift-vapor.
#
# Reads DB credentials from /home/micu/swift+vapor/.env, streams pg_dump through
# gzip and authenticated GPG encryption, and writes a timestamped file to
# /home/micu/swift-vapor-backups/. Rotates so the last 7 encrypted dumps remain.
#
# Triggered automatically by swift-vapor-backup.timer (02:00 UTC daily).
# The passphrase is supplied by systemd as the `backup-passphrase` credential.
# For a manual run, set BACKUP_PASSPHRASE_FILE to a private key file.
#
# Exit codes:
#   0  — backup written, rotation complete
#   1  — fatal (env file missing, required var unset, pg_dump failure)
#

set -euo pipefail
umask 077

ENV_FILE="/home/micu/swift+vapor/.env"
BACKUP_DIR="${BACKUP_OUTPUT_DIR:-/home/micu/swift-vapor-backups}"
RETENTION="${BACKUP_RETENTION:-7}"
LOCKFILE="${BACKUP_DIR}/.backup.lock"

if [[ "$BACKUP_DIR" != /* || "$BACKUP_DIR" == "/" ]]; then
    echo "backup: BACKUP_OUTPUT_DIR must be a specific absolute directory." >&2
    exit 1
fi
if [[ ! "$RETENTION" =~ ^[1-9][0-9]{0,2}$ ]] || (( RETENTION > 365 )); then
    echo "backup: BACKUP_RETENTION must be an integer from 1 to 365." >&2
    exit 1
fi

if [[ -n "${BACKUP_PASSPHRASE_FILE:-}" ]]; then
    PASSPHRASE_FILE="$BACKUP_PASSPHRASE_FILE"
elif [[ -n "${CREDENTIALS_DIRECTORY:-}" ]]; then
    PASSPHRASE_FILE="${CREDENTIALS_DIRECTORY}/backup-passphrase"
else
    echo "backup: no passphrase credential; use the systemd unit or set BACKUP_PASSPHRASE_FILE." >&2
    exit 1
fi

if [[ ! -f "$PASSPHRASE_FILE" ]]; then
    echo "backup: passphrase file is missing or not a regular file." >&2
    exit 1
fi
PASSPHRASE_MODE="$(stat -c '%a' "$PASSPHRASE_FILE")"
if (( (8#$PASSPHRASE_MODE & 077) != 0 )); then
    echo "backup: passphrase file must not be accessible by group or others." >&2
    exit 1
fi
if ! awk 'NR == 1 { if (length($0) < 32) exit 1; next } { exit 1 } END { if (NR != 1) exit 1 }' "$PASSPHRASE_FILE"; then
    echo "backup: passphrase must be exactly one line of at least 32 characters." >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# Single-instance guard so overlapping cron + manual runs don't both write
# half-files at the same time. Non-blocking; if another run holds the lock,
# we exit 0 and let it finish.
exec 9>"$LOCKFILE"
chmod 600 "$LOCKFILE"
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
OUT="${BACKUP_DIR}/footprint-${STAMP}.sql.gz.gpg"
[[ ! -e "$OUT" ]] || { echo "backup: refusing to overwrite $OUT" >&2; exit 1; }
TMP="$(mktemp --tmpdir="$BACKUP_DIR" ".footprint-${STAMP}.partial.XXXXXX")"
GNUPGHOME="$(mktemp -d "${TMPDIR:-/tmp}/swift-vapor-backup.XXXXXX")"
cleanup() {
    rm -f -- "$TMP"
    rm -rf -- "$GNUPGHOME"
}
trap cleanup EXIT

echo "backup: dumping ${DATABASE_NAME}@${DATABASE_HOST}:${DATABASE_PORT} -> $OUT"

# No plaintext dump is written to disk. GnuPG uses an iterated, salted S2K and
# an AEAD packet; pipefail propagates errors from pg_dump, gzip, or encryption.
PGPASSWORD="$DATABASE_PASSWORD" pg_dump \
    --host="$DATABASE_HOST" \
    --port="$DATABASE_PORT" \
    --username="$DATABASE_USERNAME" \
    --dbname="$DATABASE_NAME" \
    --no-owner --no-privileges \
    --format=plain \
    | gzip --best \
    | gpg --homedir "$GNUPGHOME" --no-options --batch --yes \
        --pinentry-mode loopback --no-symkey-cache \
        --passphrase-file "$PASSPHRASE_FILE" \
        --symmetric --force-aead --cipher-algo AES256 \
        --s2k-mode 3 --s2k-digest-algo SHA512 --compress-algo none \
        --output "$TMP"

# Verify both authenticated decryption and the compressed stream before the
# partial file is renamed into the retained backup set.
gpg --homedir "$GNUPGHOME" --no-options --batch --yes \
    --pinentry-mode loopback --no-symkey-cache \
    --passphrase-file "$PASSPHRASE_FILE" \
    --decrypt "$TMP" \
    | gzip --test

mv "$TMP" "$OUT"
chmod 600 "$OUT"
trap - EXIT
rm -rf -- "$GNUPGHOME"

# Generated names sort chronologically, so rotation does not need to parse
# human-formatted `ls` output or accept arbitrary filenames.
shopt -s nullglob
backups=("$BACKUP_DIR"/footprint-*.sql.gz.gpg)
remove_count=$(( ${#backups[@]} - RETENTION ))
for ((i = 0; i < remove_count; i++)); do
    echo "backup: rotating out ${backups[i]}"
    rm -f -- "${backups[i]}"
done

kept_count=${#backups[@]}
(( kept_count > RETENTION )) && kept_count=$RETENTION
plaintext=("$BACKUP_DIR"/footprint-*.sql.gz)
if (( ${#plaintext[@]} > 0 )); then
    echo "backup: warning: ${#plaintext[@]} legacy plaintext backup(s) still require migration." >&2
fi

SIZE="$(stat -c %s "$OUT" 2>/dev/null || echo '?')"
echo "backup: complete and verified (${SIZE} encrypted bytes, ${kept_count} kept)"
