#!/usr/bin/env bash

# Read-only backup freshness gate for monitoring and deployment. It deliberately
# does not need the encryption passphrase: backup.sh publishes a timestamp only
# after authenticated decryption and gzip verification have both succeeded.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

BACKUP_DIR="${BACKUP_OUTPUT_DIR:-/home/micu/swift-vapor-backups}"
STATUS_FILE="${BACKUP_STATUS_FILE:-${BACKUP_DIR}/.last-success}"
MAX_AGE_HOURS="${BACKUP_MAX_AGE_HOURS:-30}"

usage() {
    echo "usage: $0 [--directory ABSOLUTE_PATH] [--status-file ABSOLUTE_PATH] [--max-age-hours 1..168]" >&2
}

while (( $# > 0 )); do
    case "$1" in
        --directory) [[ $# -ge 2 ]] || { usage; exit 2; }; BACKUP_DIR="$2"; shift 2 ;;
        --status-file) [[ $# -ge 2 ]] || { usage; exit 2; }; STATUS_FILE="$2"; shift 2 ;;
        --max-age-hours) [[ $# -ge 2 ]] || { usage; exit 2; }; MAX_AGE_HOURS="$2"; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done

if [[ "$BACKUP_DIR" != /* || "$BACKUP_DIR" == "/" || ! -d "$BACKUP_DIR" ]]; then
    echo "backup-check: backup directory is missing or unsafe: $BACKUP_DIR" >&2
    exit 1
fi
if [[ "$STATUS_FILE" != /* || "$STATUS_FILE" == "/" ]]; then
    echo "backup-check: status path must be a specific absolute path." >&2
    exit 1
fi
if [[ ! "$MAX_AGE_HOURS" =~ ^[0-9]+$ ]] || (( MAX_AGE_HOURS < 1 || MAX_AGE_HOURS > 168 )); then
    echo "backup-check: max age must be an integer from 1 to 168 hours." >&2
    exit 1
fi

shopt -s nullglob
backups=("$BACKUP_DIR"/footprint-*.sql.gz.gpg)
if (( ${#backups[@]} == 0 )); then
    echo "backup-check: no encrypted backups found." >&2
    exit 1
fi

latest="${backups[0]}"
for candidate in "${backups[@]:1}"; do
    if [[ "$candidate" -nt "$latest" ]]; then latest="$candidate"; fi
done
if [[ ! -f "$latest" || -L "$latest" ]]; then
    echo "backup-check: newest backup is not a regular non-symlink file." >&2
    exit 1
fi

mode="$(stat -c '%a' "$latest")"
if (( (8#$mode & 077) != 0 )); then
    echo "backup-check: newest backup is accessible by group or others (mode $mode)." >&2
    exit 1
fi
size="$(stat -c '%s' "$latest")"
if (( size < 128 )); then
    echo "backup-check: newest backup is implausibly small (${size} bytes)." >&2
    exit 1
fi

if [[ ! -f "$STATUS_FILE" || -L "$STATUS_FILE" ]]; then
    echo "backup-check: verified-success status file is missing." >&2
    exit 1
fi
status="$(tr -d '\n' < "$STATUS_FILE")"
if [[ ! "$status" =~ ^[0-9]{10}$ ]]; then
    echo "backup-check: verified-success status is malformed." >&2
    exit 1
fi

now="$(date -u +%s)"
max_age_seconds=$(( MAX_AGE_HOURS * 3600 ))
age=$(( now - status ))
if (( age < -300 )); then
    echo "backup-check: success timestamp is implausibly in the future." >&2
    exit 1
fi
if (( age > max_age_seconds )); then
    echo "backup-check: last verified backup is stale (${age}s > ${max_age_seconds}s)." >&2
    exit 1
fi

backup_mtime="$(stat -c '%Y' "$latest")"
if (( status + 5 < backup_mtime )); then
    echo "backup-check: success timestamp predates the newest backup." >&2
    exit 1
fi

echo "backup-check: healthy (verified ${age}s ago, ${size} encrypted bytes)."
