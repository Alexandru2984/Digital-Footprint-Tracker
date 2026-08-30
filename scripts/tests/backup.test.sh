#!/usr/bin/env bash

set -euo pipefail

# The test installs a copy of itself under this name so backup.sh can execute a
# deterministic pg_dump replacement without weakening the production command.
if [[ "$(basename -- "$0")" == "mock-pg-dump" ]]; then
    # The credential must never be reachable through argv, so it must arrive as
    # a private passfile and PGPASSWORD must be gone entirely: `env -i
    # PGPASSWORD=secret` would publish the password in env's own command line.
    [[ -z "${PGPASSWORD+x}" ]]
    [[ -n "${PGPASSFILE:-}" ]]
    [[ "$(stat -c '%a' "$PGPASSFILE")" == "600" ]]
    [[ "$(stat -c '%a' "$(dirname -- "$PGPASSFILE")")" == "700" ]]
    # env -i means expectations cannot be passed in; report the observed line
    # back through a path derived from $0 and let the harness assert on it.
    cp -- "$PGPASSFILE" "$(dirname -- "$0")/observed-pgpass"
    [[ "${PGCONNECT_TIMEOUT:-}" == "10" ]]
    [[ -z "${HOME+x}" ]]
    expected=(
        --host=127.0.0.1
        --port=5432
        --username=footprint_test
        --dbname=footprint_test
        --no-owner
        --no-privileges
        --format=plain
    )
    actual=("$@")
    [[ "$#" -eq "${#expected[@]}" ]]
    for index in "${!expected[@]}"; do
        [[ "${actual[index]}" == "${expected[index]}" ]]
    done
    printf '%s\n' 'CREATE TABLE backup_contract (id integer);'
    exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

MOCK_PG_DUMP="$TMP/mock-pg-dump"
DATABASE_SECRET="$TMP/database-password"
BACKUP_SECRET="$TMP/backup-passphrase"
OUTPUT="$TMP/artifacts"
STATUS="$TMP/status/last-success"
VERIFY_HOME="$TMP/verify-gnupg"

install -m 0755 "$0" "$MOCK_PG_DUMP"
printf 'd%.0s' {1..24} > "$DATABASE_SECRET"
printf '\n' >> "$DATABASE_SECRET"
printf 'p%.0s' {1..48} > "$BACKUP_SECRET"
printf '\n' >> "$BACKUP_SECRET"
chmod 0600 "$DATABASE_SECRET" "$BACKUP_SECRET"
mkdir -m 0700 "$VERIFY_HOME"

run_backup() {
    DATABASE_HOST=127.0.0.1 \
    DATABASE_PORT=5432 \
    DATABASE_USERNAME=footprint_test \
    DATABASE_NAME=footprint_test \
    DATABASE_PASSWORD_FILE="$DATABASE_SECRET" \
    BACKUP_PASSPHRASE_FILE="$BACKUP_SECRET" \
    BACKUP_OUTPUT_DIR="$OUTPUT" \
    BACKUP_STATUS_FILE="$STATUS" \
    BACKUP_RETENTION=1 \
    PG_DUMP_PATH="$MOCK_PG_DUMP" \
        "$ROOT/scripts/backup.sh"
}

run_backup >/dev/null
[[ "$(cat "$TMP/observed-pgpass")" == "*:*:footprint_test:footprint_test:dddddddddddddddddddddddd" ]]
mapfile -t artifacts < <(find "$OUTPUT" -maxdepth 1 -type f -name 'footprint-*.sql.gz.gpg' -print)
[[ "${#artifacts[@]}" -eq 1 ]]
[[ "$(stat -c '%a' "${artifacts[0]}")" == "600" ]]
[[ "$(stat -c '%a' "$STATUS")" == "644" ]]
[[ "$(tr -d '\n' < "$STATUS")" =~ ^[0-9]{10}$ ]]
[[ -z "$(find "$OUTPUT" -maxdepth 1 -type f -name '*.sql.gz' -print -quit)" ]]

gpg --homedir "$VERIFY_HOME" --no-options --batch --yes \
    --pinentry-mode loopback --no-symkey-cache \
    --passphrase-file "$BACKUP_SECRET" \
    --decrypt "${artifacts[0]}" 2>/dev/null \
    | gzip --decompress \
    | grep -qF 'CREATE TABLE backup_contract'

"$ROOT/scripts/check-backup.sh" \
    --directory "$OUTPUT" \
    --status-file "$STATUS" \
    --max-age-hours 1 >/dev/null

if DATABASE_PASSWORD=inline-is-forbidden run_backup >/dev/null 2>&1; then
    echo "expected an inline database password to fail" >&2
    exit 1
fi

chmod 0644 "$DATABASE_SECRET"
if run_backup >/dev/null 2>&1; then
    echo "expected a permissive database credential to fail" >&2
    exit 1
fi
chmod 0600 "$DATABASE_SECRET"

sleep 1
run_backup >/dev/null
[[ "$(find "$OUTPUT" -maxdepth 1 -type f -name 'footprint-*.sql.gz.gpg' | wc -l)" -eq 1 ]]

# A password containing the characters .pgpass reserves must reach libpq
# intact: an unescaped colon would silently shift every field and libpq would
# then look up a password that does not exist. Backslash first, then colon —
# the reverse order would double-escape the escapes.
printf '%s' 'pa:ss\\word:x' > "$DATABASE_SECRET"
printf '\n' >> "$DATABASE_SECRET"
chmod 0600 "$DATABASE_SECRET"
sleep 1
run_backup >/dev/null
[[ "$(cat "$TMP/observed-pgpass")" == '*:*:footprint_test:footprint_test:pa\:ss\\\\word\:x' ]]

echo "encrypted backup contract tests passed"
