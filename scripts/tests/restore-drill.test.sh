#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

PASSPHRASE="$TMP/passphrase"
BACKUP="$TMP/footprint-2026-08-24_00-00-00.sql.gz.gpg"
MANIFEST="$TMP/restore-manifest.json"
FAKE_BIN="$TMP/bin"
ENGINE_LOG="$TMP/engine.log"
IMAGE="postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
mkdir -m 0700 "$FAKE_BIN"
printf '%s\n' 'correct-horse-battery-staple-restore-drill-secret' > "$PASSPHRASE"
chmod 0600 "$PASSPHRASE"

GNUPGHOME="$TMP/fixture-gnupg"
mkdir -m 0700 "$GNUPGHOME"
{
    printf '%s\n' 'CREATE TABLE recovery_probe (id bigint PRIMARY KEY, marker text NOT NULL);'
    for value in {1..32}; do
        printf "INSERT INTO recovery_probe VALUES (%d, 'marker-%08d-a5f94e21');\n" "$value" "$value"
    done
} | gzip --best \
    | gpg --homedir "$GNUPGHOME" --no-options --batch --yes \
        --pinentry-mode loopback --no-symkey-cache \
        --passphrase-file "$PASSPHRASE" --symmetric --cipher-algo AES256 \
        --output "$BACKUP"
chmod 0600 "$BACKUP"
BACKUP_SHA_BEFORE="$(sha256sum "$BACKUP" | cut -d' ' -f1)"

cat > "$FAKE_BIN/docker" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${FAKE_ENGINE_LOG:?}"

case "${1:-}" in
    image)
        [[ "${2:-}" == "inspect" ]]
        ;;
    run)
        printf '%s\n' 'fake-container-id'
        ;;
    inspect)
        printf '%s\n' 'true'
        ;;
    rm)
        ;;
    version)
        printf '%s\n' '26.0.0-test'
        ;;
    exec)
        shift
        if [[ "${1:-}" == "--interactive" ]]; then shift; fi
        [[ $# -ge 2 ]]
        shift
        command_name="$1"
        shift
        case "$command_name" in
            pg_isready)
                ;;
            psql)
                if [[ "$*" == *"information_schema.tables"* ]]; then
                    printf '%s\n' '3'
                elif [[ "$*" == *"pg_database_size"* ]]; then
                    printf '%s\n' '32768'
                elif [[ "$*" == *"server_version_num"* ]]; then
                    printf '%s\n' '160010'
                else
                    restored_sql="$(cat)"
                    [[ "$restored_sql" == *"CREATE TABLE recovery_probe"* ]]
                fi
                ;;
            pg_dump)
                printf '%s\n' 'verified logical read-back fixture'
                ;;
            *)
                echo "unexpected fake-engine exec command: $command_name" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo "unexpected fake-engine command: ${1:-missing}" >&2
        exit 1
        ;;
esac
FAKE
chmod 0755 "$FAKE_BIN/docker"

FAKE_ENGINE_LOG="$ENGINE_LOG" "$ROOT/scripts/restore-drill.sh" \
    --backup "$BACKUP" \
    --passphrase-file "$PASSPHRASE" \
    --manifest "$MANIFEST" \
    --engine "$FAKE_BIN/docker" \
    --image "$IMAGE" >/dev/null

[[ -f "$BACKUP" && ! -L "$BACKUP" ]]
[[ "$(sha256sum "$BACKUP" | cut -d' ' -f1)" == "$BACKUP_SHA_BEFORE" ]]
[[ "$(stat -c '%a' "$MANIFEST")" == "600" ]]
grep -F -- '--network none' "$ENGINE_LOG" >/dev/null
grep -F -- 'rm --force swift-vapor-restore-' "$ENGINE_LOG" >/dev/null
if grep -E -- '(^| )(-v|--volume)( |$)' "$ENGINE_LOG" >/dev/null; then
    echo "restore drill unexpectedly mounted a host path" >&2
    exit 1
fi

python3 - "$MANIFEST" "$BACKUP_SHA_BEFORE" "$IMAGE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    manifest = json.load(stream)

assert manifest["schema_version"] == 1
assert manifest["status"] == "succeeded"
assert manifest["backup"]["sha256"] == sys.argv[2]
assert manifest["backup"]["preserved"] is True
assert manifest["restore"]["postgres_image"] == sys.argv[3]
assert manifest["restore"]["public_base_table_count"] == 3
assert manifest["restore"]["database_disposed_before_success"] is True
assert manifest["isolation"] == {
    "container_engine": "docker",
    "host_mounts": False,
    "network": "none",
    "plaintext_dump_written_to_host": False,
}
assert "/" not in manifest["backup"]["filename"]
PY

if FAKE_ENGINE_LOG="$ENGINE_LOG" "$ROOT/scripts/restore-drill.sh" \
    --backup "$BACKUP" --passphrase-file "$PASSPHRASE" \
    --manifest "$TMP/unpinned.json" --engine "$FAKE_BIN/docker" \
    --image postgres:16-alpine >/dev/null 2>&1; then
    echo "expected an unpinned image to be rejected" >&2
    exit 1
fi

ln -s "$BACKUP" "$TMP/backup-link.gpg"
if FAKE_ENGINE_LOG="$ENGINE_LOG" "$ROOT/scripts/restore-drill.sh" \
    --backup "$TMP/backup-link.gpg" --passphrase-file "$PASSPHRASE" \
    --manifest "$TMP/symlink.json" --engine "$FAKE_BIN/docker" \
    --image "$IMAGE" >/dev/null 2>&1; then
    echo "expected a symlink backup to be rejected" >&2
    exit 1
fi

WRONG_PASSPHRASE="$TMP/wrong-passphrase"
FAILED_MANIFEST="$TMP/failed-restore.json"
printf '%s\n' 'wrong-but-still-long-enough-restore-drill-passphrase' > "$WRONG_PASSPHRASE"
chmod 0600 "$WRONG_PASSPHRASE"
REMOVALS_BEFORE="$(grep -c -F -- 'rm --force swift-vapor-restore-' "$ENGINE_LOG")"
if FAKE_ENGINE_LOG="$ENGINE_LOG" "$ROOT/scripts/restore-drill.sh" \
    --backup "$BACKUP" --passphrase-file "$WRONG_PASSPHRASE" \
    --manifest "$FAILED_MANIFEST" --engine "$FAKE_BIN/docker" \
    --image "$IMAGE" >/dev/null 2>&1; then
    echo "expected a failed decryption to fail the drill" >&2
    exit 1
fi
REMOVALS_AFTER="$(grep -c -F -- 'rm --force swift-vapor-restore-' "$ENGINE_LOG")"
[[ ! -e "$FAILED_MANIFEST" ]]
(( REMOVALS_AFTER > REMOVALS_BEFORE ))

chmod 0644 "$PASSPHRASE"
if FAKE_ENGINE_LOG="$ENGINE_LOG" "$ROOT/scripts/restore-drill.sh" \
    --backup "$BACKUP" --passphrase-file "$PASSPHRASE" \
    --manifest "$TMP/open-secret.json" --engine "$FAKE_BIN/docker" \
    --image "$IMAGE" >/dev/null 2>&1; then
    echo "expected a permissive passphrase file to be rejected" >&2
    exit 1
fi
chmod 0600 "$PASSPHRASE"

if FAKE_ENGINE_LOG="$ENGINE_LOG" "$ROOT/scripts/restore-drill.sh" \
    --backup "$BACKUP" --passphrase-file "$PASSPHRASE" \
    --manifest "$MANIFEST" --engine "$FAKE_BIN/docker" \
    --image "$IMAGE" >/dev/null 2>&1; then
    echo "expected an existing manifest to be protected from overwrite" >&2
    exit 1
fi

echo "restore drill tests passed"
