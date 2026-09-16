#!/usr/bin/env bash

set -euo pipefail

# The off-host copy is the last thing standing after the host is gone, so the
# property that matters is not "it uploaded" but "it only claims success after
# re-reading the far side". Every case drives the real script with a stand-in
# rclone that records its arguments, and with TMPDIR pointing at a directory
# that does not exist (see F22).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHIPPER="$ROOT/scripts/offsite-backup.sh"
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

fail() { echo "offsite-backup contract: $1" >&2; exit 1; }

SRC="$TMP/artifacts"; STATE="$TMP/state"; mkdir -p "$SRC" "$STATE"
printf 'ciphertext\n' > "$SRC/footprint-2026-09-16_05-00-00.sql.gz.gpg"
printf 'ciphertext\n' > "$SRC/footprint-2026-09-15_05-00-00.sql.gz.gpg"
printf 'not an artifact\n' > "$SRC/README.txt"
CONF="$TMP/rclone.conf"; printf '[gdrive]\ntype = drive\n' > "$CONF"; chmod 0600 "$CONF"

MOCK="$TMP/rclone"
cat > "$MOCK" <<'MOCKEOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${MOCK_LOG}"
subcommand="$1"
status_var="MOCK_${subcommand^^}_STATUS"
exit "${!status_var:-0}"
MOCKEOF
chmod 0755 "$MOCK"

ship() {
    env -i PATH="$PATH" HOME="$TMP" TMPDIR="$TMP/no-scratch-space" \
        MOCK_LOG="$TMP/rclone.log" \
        MOCK_COPY_STATUS="${COPY_STATUS:-0}" MOCK_CHECK_STATUS="${CHECK_STATUS:-0}" \
        OFFSITE_RCLONE="$MOCK" OFFSITE_RCLONE_CONFIG="$CONF" \
        OFFSITE_SOURCE_DIR="$SRC" OFFSITE_STATUS_FILE="$STATE/last-success" \
        OFFSITE_REMOTE="${REMOTE-gdrive:Backup_VPS/swift-vapor}" \
        "$SHIPPER"
}

# 1. Happy path: copy then verify, and only then a status file.
: > "$TMP/rclone.log"
ship >/dev/null || fail "expected a clean run to succeed"
grep -q '^copy ' "$TMP/rclone.log" || fail "expected an rclone copy"
grep -q '^check ' "$TMP/rclone.log" || fail "expected an rclone check"
grep '^copy ' "$TMP/rclone.log" | grep -q -- '--immutable' \
    || fail "the copy must refuse to rewrite remote history (--immutable)"
grep '^copy ' "$TMP/rclone.log" | grep -q -- '--checksum' || fail "the copy must compare checksums"
grep '^check ' "$TMP/rclone.log" | grep -q -- '--one-way' \
    || fail "the verification must be one-way (the remote keeps files we rotated away)"
grep -q -- "--include footprint-\*.sql.gz.gpg" "$TMP/rclone.log" \
    || fail "only the encrypted artifacts may be shipped"
[[ -f "$STATE/last-success" ]] || fail "expected a status file"
[[ "$(stat -c '%a' "$STATE/last-success")" == "644" ]] || fail "status file should be world-readable, no secret in it"
grep -q "verified=2" "$STATE/last-success" || fail "expected the verified artifact count"
grep -q "remote=gdrive:Backup_VPS/swift-vapor" "$STATE/last-success" || fail "expected the destination recorded"

# Nothing may ever be deleted on the far side.
grep -qE '^(delete|purge|sync|rmdir|cleanup) ' "$TMP/rclone.log" \
    && fail "this must never delete remotely"

# 2. A failed upload publishes nothing.
rm -f "$STATE/last-success"; : > "$TMP/rclone.log"
if COPY_STATUS=1 ship >/dev/null 2>&1; then fail "expected a failed upload to fail"; fi
[[ ! -f "$STATE/last-success" ]] || fail "a failed upload must not publish success"

# 3. The case that matters: the upload "worked" but verification disagrees.
: > "$TMP/rclone.log"
if CHECK_STATUS=1 ship >/dev/null 2>&1; then fail "expected failed verification to fail"; fi
[[ ! -f "$STATE/last-success" ]] || fail "unverified data must never be recorded as a copy"

# 4. An empty artifact directory is a problem, not a quiet success.
EMPTY="$TMP/empty"; mkdir -p "$EMPTY"
if OFFSITE_SOURCE_DIR_OVERRIDE=1 env -i PATH="$PATH" HOME="$TMP" MOCK_LOG="$TMP/rclone.log" \
    OFFSITE_RCLONE="$MOCK" OFFSITE_RCLONE_CONFIG="$CONF" OFFSITE_SOURCE_DIR="$EMPTY" \
    OFFSITE_STATUS_FILE="$STATE/last-success" OFFSITE_REMOTE="gdrive:x" "$SHIPPER" >/dev/null 2>&1; then
    fail "expected an empty artifact directory to fail"
fi

# 5. A destination that could turn into an option, or into nothing at all.
for bad in "--config=/etc/shadow" "" "gdrive:; rm -rf /" "gdrive:\$(id)"; do
    if REMOTE="$bad" ship >/dev/null 2>&1; then fail "expected the destination '$bad' to be refused"; fi
done

# 6. A config anyone can read is a credential problem.
chmod 0644 "$CONF"
if ship >/dev/null 2>&1; then fail "expected a world-readable rclone config to be refused"; fi
chmod 0600 "$CONF"
ship >/dev/null || fail "expected the run to recover once the config is private again"

echo "offsite-backup contract tests passed"
