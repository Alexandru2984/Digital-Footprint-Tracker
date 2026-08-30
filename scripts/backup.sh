#!/usr/bin/env bash

# Encrypted PostgreSQL backup for swift-vapor. Database and encryption secrets
# are accepted only through private files (normally systemd credentials). The
# SQL stream is never written to disk in plaintext.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077

BACKUP_DIR="${BACKUP_OUTPUT_DIR:-/var/lib/swift-vapor-backup/artifacts}"
STATUS_FILE="${BACKUP_STATUS_FILE:-/var/lib/swift-vapor-backup/status/last-success}"
RETENTION="${BACKUP_RETENTION:-7}"
PG_DUMP_PATH="${PG_DUMP_PATH:-/usr/bin/pg_dump}"
LOCKFILE="$BACKUP_DIR/.backup.lock"

die() {
    echo "backup: $*" >&2
    exit 1
}

validate_path() {
    local label="$1" path="$2"
    [[ "$path" == /* && "$path" != "/" && "$path" != *$'\n'* && "$path" != *$'\r'* ]] \
        || die "$label must be a specific absolute path."
}

read_private_scalar() {
    local label="$1" path="$2" destination="$3" minimum_length="$4"
    local mode size
    local -a lines=()

    validate_path "$label file" "$path"
    [[ -f "$path" && ! -L "$path" ]] || die "$label file is missing or unsafe."
    mode="$(stat -c '%a' "$path")"
    # systemd's LoadCredentialEncrypted= always materializes credentials as
    # root:root 0440 plus a POSIX ACL scoped to the executing unit's user —
    # the on-disk group-read bit is inherent to that mechanism, not a leak;
    # the ACL is what actually gates access. Reject only world access.
    (( (8#$mode & 007) == 0 )) || die "$label file must not be accessible by others."
    size="$(stat -c '%s' "$path")"
    (( size > 0 && size <= 16384 )) || die "$label file has an invalid size."
    cmp -s -- "$path" <(tr -d '\000' < "$path") || die "$label file contains an invalid value."
    mapfile -t lines < "$path"
    (( ${#lines[@]} == 1 )) || die "$label must contain exactly one line."
    (( ${#lines[0]} >= minimum_length )) || die "$label is shorter than required."
    [[ "${lines[0]}" != *$'\r'* ]] || die "$label contains an invalid value."
    printf -v "$destination" '%s' "${lines[0]}"
}

validate_private_scalar() {
    local scratch=""
    read_private_scalar "$1" "$2" scratch "$3"
    [[ -n "$scratch" ]]
    scratch=""
}

validate_path "BACKUP_OUTPUT_DIR" "$BACKUP_DIR"
validate_path "BACKUP_STATUS_FILE" "$STATUS_FILE"
if [[ ! "$RETENTION" =~ ^[1-9][0-9]{0,2}$ ]] || (( RETENTION > 365 )); then
    die "BACKUP_RETENTION must be an integer from 1 to 365."
fi
validate_path "PG_DUMP_PATH" "$PG_DUMP_PATH"
[[ -f "$PG_DUMP_PATH" && ! -L "$PG_DUMP_PATH" && -x "$PG_DUMP_PATH" ]] \
    || die "PG_DUMP_PATH must be an executable regular file."

[[ -z "${DATABASE_PASSWORD:-}" ]] \
    || die "DATABASE_PASSWORD is forbidden; use DATABASE_PASSWORD_FILE."
[[ -z "${BACKUP_PASSPHRASE:-}" ]] \
    || die "BACKUP_PASSPHRASE is forbidden; use BACKUP_PASSPHRASE_FILE."
: "${DATABASE_PASSWORD_FILE:?DATABASE_PASSWORD_FILE is required}"
: "${BACKUP_PASSPHRASE_FILE:?BACKUP_PASSPHRASE_FILE is required}"
: "${DATABASE_HOST:?DATABASE_HOST is required}"
: "${DATABASE_NAME:?DATABASE_NAME is required}"
: "${DATABASE_USERNAME:?DATABASE_USERNAME is required}"
: "${DATABASE_PORT:=5432}"

case "$DATABASE_HOST" in
    127.0.0.1|localhost|::1|/run/postgresql|/var/run/postgresql) ;;
    *) die "DATABASE_HOST must resolve through an approved local endpoint." ;;
esac
if [[ ! "$DATABASE_PORT" =~ ^[0-9]{1,5}$ ]] \
    || (( DATABASE_PORT < 1 || DATABASE_PORT > 65535 )); then
    die "DATABASE_PORT must be an integer from 1 to 65535."
fi
[[ "$DATABASE_NAME" =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,62}$ ]] \
    || die "DATABASE_NAME contains unsupported characters."
[[ "$DATABASE_USERNAME" =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,62}$ ]] \
    || die "DATABASE_USERNAME contains unsupported characters."

DATABASE_PASSWORD=""
read_private_scalar "database password" "$DATABASE_PASSWORD_FILE" DATABASE_PASSWORD 1
validate_private_scalar "backup passphrase" "$BACKUP_PASSPHRASE_FILE" 32

mkdir -p -- "$BACKUP_DIR"
[[ -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] || die "backup directory is unsafe."
chmod 0750 "$BACKUP_DIR"
STATUS_DIR="$(dirname -- "$STATUS_FILE")"
mkdir -p -- "$STATUS_DIR"
[[ -d "$STATUS_DIR" && ! -L "$STATUS_DIR" ]] || die "status directory is unsafe."

# A non-blocking single-instance guard prevents cron/manual overlap from
# publishing or rotating half-written generations.
exec 9>"$LOCKFILE"
chmod 0600 "$LOCKFILE"
if ! flock -n 9; then
    echo "backup: another run is in progress, skipping." >&2
    exit 0
fi

STAMP="$(date -u +%Y-%m-%d_%H-%M-%S)"
OUT="$BACKUP_DIR/footprint-${STAMP}.sql.gz.gpg"
[[ ! -e "$OUT" && ! -L "$OUT" ]] || die "refusing to overwrite an existing generation."
TMP="$(mktemp --tmpdir="$BACKUP_DIR" ".footprint-${STAMP}.partial.XXXXXX")"
GNUPGHOME="$(mktemp -d "${TMPDIR:-/tmp}/swift-vapor-backup.XXXXXX")"
PRIVATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swift-vapor-backup.XXXXXX")"
cleanup() {
    if [[ -n "${TMP:-}" && "$TMP" == "$BACKUP_DIR"/.footprint-*.partial.* ]]; then
        rm -f -- "$TMP"
    fi
    if [[ -n "${GNUPGHOME:-}" && "$GNUPGHOME" == "${TMPDIR:-/tmp}"/swift-vapor-backup.* ]]; then
        rm -rf -- "$GNUPGHOME"
    fi
    if [[ -n "${PRIVATE_DIR:-}" && "$PRIVATE_DIR" == "${TMPDIR:-/tmp}"/swift-vapor-backup.* ]]; then
        rm -rf -- "$PRIVATE_DIR"
    fi
}
trap cleanup EXIT

echo "backup: dumping ${DATABASE_NAME}@${DATABASE_HOST}:${DATABASE_PORT}"

# The password reaches libpq through a private passfile, not through PGPASSWORD.
# `env -i ... PGPASSWORD=secret` puts the credential in *env's own argv*, and
# /proc/<pid>/cmdline is world-readable: on a host shared with other service
# accounts, anything sampling /proc during env's fork-to-exec window reads the
# database password. A passfile path in argv discloses nothing.
#
# Host and port are wildcards because DATABASE_HOST is already restricted to
# approved local endpoints above; that keeps one line correct for both TCP and
# Unix-socket connections without re-deriving libpq's matching rules. Only the
# password can contain the characters the format reserves — the database and
# user names are pattern-validated above — so only it needs escaping.
PGPASS_FILE="$PRIVATE_DIR/pgpass"
pgpass_password="${DATABASE_PASSWORD//\\/\\\\}"
pgpass_password="${pgpass_password//:/\\:}"
( umask 077; printf '*:*:%s:%s:%s\n' \
    "$DATABASE_NAME" "$DATABASE_USERNAME" "$pgpass_password" > "$PGPASS_FILE" )
pgpass_password=""
[[ "$(stat -c '%a' "$PGPASS_FILE")" == "600" ]] || die "passfile permissions are unsafe."

# `env -i` prevents libpq configuration inherited from an operator session or
# service manager from redirecting the dump. Pipefail propagates every stage.
env -i PATH="$PATH" LC_ALL=C PGPASSFILE="$PGPASS_FILE" PGCONNECT_TIMEOUT=10 \
    "$PG_DUMP_PATH" \
    --host="$DATABASE_HOST" \
    --port="$DATABASE_PORT" \
    --username="$DATABASE_USERNAME" \
    --dbname="$DATABASE_NAME" \
    --no-owner --no-privileges \
    --format=plain \
    | gzip --best \
    | gpg --homedir "$GNUPGHOME" --no-options --batch --yes \
        --pinentry-mode loopback --no-symkey-cache \
        --passphrase-file "$BACKUP_PASSPHRASE_FILE" \
        --symmetric --force-aead --cipher-algo AES256 \
        --s2k-mode 3 --s2k-digest-algo SHA512 --compress-algo none \
        --output "$TMP"
DATABASE_PASSWORD=""
rm -f -- "$PGPASS_FILE"

# Authenticated decryption and gzip verification must pass before publication.
gpg --homedir "$GNUPGHOME" --no-options --batch --yes \
    --pinentry-mode loopback --no-symkey-cache \
    --passphrase-file "$BACKUP_PASSPHRASE_FILE" \
    --decrypt "$TMP" \
    | gzip --test

SIZE="$(stat -c '%s' "$TMP")"
(( SIZE >= 128 )) || die "encrypted output is implausibly small."
mv -- "$TMP" "$OUT"
TMP=""
chmod 0600 "$OUT"
rm -rf -- "$GNUPGHOME"
GNUPGHOME=""

# Generated UTC names sort chronologically, so retention never parses `ls` or
# accepts a caller-controlled removal target.
shopt -s nullglob
backups=("$BACKUP_DIR"/footprint-*.sql.gz.gpg)
remove_count=$(( ${#backups[@]} - RETENTION ))
for ((i = 0; i < remove_count; i++)); do
    echo "backup: rotating out $(basename -- "${backups[i]}")"
    rm -f -- "${backups[i]}"
done

backups=("$BACKUP_DIR"/footprint-*.sql.gz.gpg)
kept_count=${#backups[@]}
plaintext=("$BACKUP_DIR"/footprint-*.sql.gz)
if (( ${#plaintext[@]} > 0 )); then
    echo "backup: warning: ${#plaintext[@]} legacy plaintext backup(s) require controlled migration." >&2
fi

# Publish only a non-secret freshness timestamp, atomically and only after the
# retained artifact has passed both verification stages.
STATUS_TMP="$(mktemp --tmpdir="$STATUS_DIR" .last-success.partial.XXXXXX)"
printf '%s\n' "$(date -u +%s)" > "$STATUS_TMP"
chmod 0644 "$STATUS_TMP"
mv -f -- "$STATUS_TMP" "$STATUS_FILE"

trap - EXIT
echo "backup: complete and verified (${SIZE} encrypted bytes, ${kept_count} kept)"
