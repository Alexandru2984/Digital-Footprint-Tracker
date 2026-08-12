#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

BACKUP="$TMP/footprint-2026-08-12_00-00-00.sql.gz.gpg"
STATUS="$TMP/last-success"
dd if=/dev/zero of="$BACKUP" bs=256 count=1 status=none
chmod 600 "$BACKUP"
date -u +%s > "$STATUS"

"$ROOT/scripts/check-backup.sh" --directory "$TMP" --status-file "$STATUS" --max-age-hours 1 >/dev/null

chmod 0644 "$BACKUP"
if "$ROOT/scripts/check-backup.sh" --directory "$TMP" --status-file "$STATUS" --max-age-hours 1 >/dev/null 2>&1; then
    echo "expected permissive backup mode to fail" >&2
    exit 1
fi
chmod 0600 "$BACKUP"

printf '%s\n' "$(( $(date -u +%s) - 7200 ))" > "$STATUS"
if "$ROOT/scripts/check-backup.sh" --directory "$TMP" --status-file "$STATUS" --max-age-hours 1 >/dev/null 2>&1; then
    echo "expected stale status to fail" >&2
    exit 1
fi

echo "backup checker tests passed"
