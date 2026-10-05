#!/usr/bin/env bash

# Ships the encrypted database backups to an off-host destination.
#
# backup.sh has already GPG-encrypted each artifact and proved it by
# authenticated decryption before publishing it, so the remote only ever sees
# ciphertext and this adds no second encryption layer. That is deliberate:
# recovery needs the backup passphrase and nothing else. An off-host copy that
# additionally needs a secret kept only on the host it exists to survive is not
# a copy — see docs/RECOVERY_DRILL.md.
#
# It never deletes anything remotely. Deletion is the part of every backup tool
# that loses data: a mirror propagates a local wipe, and a retention pass that
# runs while local backups are failing removes the last good copies. Pruning the
# remote stays a deliberate, human act.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SOURCE_DIR="${OFFSITE_SOURCE_DIR:-/var/lib/swift-vapor-backup/artifacts}"
# One or more destinations, space separated. OFFSITE_REMOTE is still read so
# an installed environment file from before this was plural keeps working.
REMOTES_RAW="${OFFSITE_REMOTES:-${OFFSITE_REMOTE:-}}"
RCLONE="${OFFSITE_RCLONE:-/usr/bin/rclone}"
CONFIG_FILE="${OFFSITE_RCLONE_CONFIG:-}"
STATUS_FILE="${OFFSITE_STATUS_FILE:-/var/lib/swift-vapor-offsite/last-success}"
TRANSFERS="${OFFSITE_TRANSFERS:-2}"
ARTIFACT_GLOB='footprint-*.sql.gz.gpg'

die() { echo "offsite-backup: $*" >&2; exit 1; }

# Bash evaluates a (( )) operand as an expression, so an unvalidated value there
# is code execution rather than a wrong number.
[[ "$TRANSFERS" =~ ^[1-9][0-9]?$ ]] || die "OFFSITE_TRANSFERS must be 1..99."

# The remote is a caller-supplied string that becomes an rclone argument. It
# cannot reach a shell — nothing here uses eval — but a value starting with '-'
# would become an option instead of a path, so keep it to what a remote name and
# path actually need.
[[ -n "$REMOTES_RAW" ]] || die "OFFSITE_REMOTES is not configured."
# Split without a here-string: those stage through a temp file for large input,
# and this unit runs with a private /tmp that a full host /tmp makes read-only.
mapfile -t REMOTES < <(printf '%s' "$REMOTES_RAW" | tr -s ' \t' '\n' | grep -v '^$')
(( ${#REMOTES[@]} > 0 )) || die "OFFSITE_REMOTES holds no destination."
for remote in "${REMOTES[@]}"; do
    [[ "$remote" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*:[A-Za-z0-9_./-]*$ ]] \
        || die "destination '$remote' must look like 'remote:path' and hold no surprising characters."
done

for path in "$SOURCE_DIR" "$STATUS_FILE" "$CONFIG_FILE"; do
    [[ "$path" == /* ]] || die "expected an absolute path, got: ${path:-<unset>}"
done
[[ -x "$RCLONE" ]] || die "rclone is missing or not executable at $RCLONE."
[[ -d "$SOURCE_DIR" ]] || die "the artifact directory is missing: $SOURCE_DIR"

# A symlinked or group/world-readable config is a credential handling problem,
# not a convenience: it carries the token that can write to the destination.
[[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || die "the rclone config is missing or not a regular file."
config_mode="$(stat -c '%a' "$CONFIG_FILE")"
case "$config_mode" in
    400|600|640) ;;
    *) die "the rclone config permissions are unsafe ($config_mode)." ;;
esac

# Nothing to ship is a problem, not a quiet success: it means backup.sh has not
# produced an artifact, and the run that would have caught that is this one.
mapfile -d '' -t artifacts < <(find "$SOURCE_DIR" -maxdepth 1 -type f -name "$ARTIFACT_GLOB" -print0)
(( ${#artifacts[@]} > 0 )) || die "no $ARTIFACT_GLOB artifacts in $SOURCE_DIR."

STATUS_DIR="$(dirname -- "$STATUS_FILE")"
[[ -d "$STATUS_DIR" ]] || die "the status directory is missing: $STATUS_DIR"

common=(
    --config "$CONFIG_FILE"
    --include "$ARTIFACT_GLOB"
    --transfers "$TRANSFERS"
    --checkers 4
    --retries 3
    --low-level-retries 10
    --timeout 5m
    --contimeout 30s
    --stats 0
    --log-level NOTICE
)

# Each destination is copied and then verified on its own, and the status below
# is published only if every one of them held. Two destinations exist so that a
# single provider — an expiring OAuth client, a quota, a deleted folder — cannot
# take the only off-host copy with it.
echo "offsite-backup: copying ${#artifacts[@]} artifact(s) to ${#REMOTES[@]} destination(s)"
for remote in "${REMOTES[@]}"; do
    # --immutable refuses to replace a remote file whose content differs: a name
    # already on the far side is history, and history is not rewritten from here.
    "$RCLONE" copy "$SOURCE_DIR" "$remote" "${common[@]}" --immutable --checksum \
        || die "upload to $remote failed."

    # Upload success only means the transfers returned. This re-reads the far
    # side and compares checksums, so the claim below is about what is there.
    "$RCLONE" check "$SOURCE_DIR" "$remote" "${common[@]}" --one-way --checksum \
        || die "post-upload verification at $remote failed."

    echo "offsite-backup: verified ${#artifacts[@]} artifact(s) at $remote"
done

# Published only after verification, and staged in its own directory rather than
# /tmp — on this shared host a full /tmp leaves sandboxed units a read-only one
# (see healthcheck.sh, "Shared scratch space").
STATUS_TMP="$(mktemp --tmpdir="$STATUS_DIR" .last-success.partial.XXXXXX)"
trap 'rm -f -- "$STATUS_TMP"' EXIT
destinations="$(printf '%s,' "${REMOTES[@]}")"
printf '%s verified=%d destinations=%s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${#artifacts[@]}" "${destinations%,}" > "$STATUS_TMP"
chmod 0644 "$STATUS_TMP"
mv -f -- "$STATUS_TMP" "$STATUS_FILE"
trap - EXIT

echo "offsite-backup: ${#artifacts[@]} artifact(s) verified at every destination (${#REMOTES[@]})"
