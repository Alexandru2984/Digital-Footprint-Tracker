#!/usr/bin/env bash

# Restore one encrypted PostgreSQL backup inside a disposable, networkless
# container and publish a non-secret JSON recovery manifest. No plaintext dump
# or database volume is ever written to the host.

set -euo pipefail
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

DEFAULT_IMAGE="postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
BACKUP=""
PASSPHRASE_FILE=""
MANIFEST=""
IMAGE="${RESTORE_DRILL_POSTGRES_IMAGE:-$DEFAULT_IMAGE}"
ENGINE="${RESTORE_DRILL_ENGINE:-}"
READY_TIMEOUT="${RESTORE_DRILL_READY_TIMEOUT_SECONDS:-60}"

usage() {
    cat >&2 <<'EOF'
usage: restore-drill.sh --backup ABSOLUTE_FILE --manifest ABSOLUTE_FILE
                        [--passphrase-file ABSOLUTE_FILE]
                        [--engine ABSOLUTE_DOCKER_OR_PODMAN]
                        [--image NAME@sha256:DIGEST]

The passphrase defaults to $CREDENTIALS_DIRECTORY/backup-passphrase when the
script is launched by systemd with LoadCredentialEncrypted=.
EOF
}

die() {
    echo "restore-drill: $*" >&2
    exit 1
}

while (( $# > 0 )); do
    case "$1" in
        --backup)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            BACKUP="$2"
            shift 2
            ;;
        --passphrase-file)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            PASSPHRASE_FILE="$2"
            shift 2
            ;;
        --manifest)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            MANIFEST="$2"
            shift 2
            ;;
        --engine)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            ENGINE="$2"
            shift 2
            ;;
        --image)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            IMAGE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

[[ -n "$BACKUP" && -n "$MANIFEST" ]] || { usage; exit 2; }
if [[ -z "$PASSPHRASE_FILE" && -n "${CREDENTIALS_DIRECTORY:-}" ]]; then
    PASSPHRASE_FILE="${CREDENTIALS_DIRECTORY}/backup-passphrase"
fi
[[ -n "$PASSPHRASE_FILE" ]] || die "no passphrase credential; use --passphrase-file or systemd LoadCredentialEncrypted=."

[[ "$BACKUP" == /* && "$BACKUP" != "/" ]] || die "backup must be a specific absolute path."
[[ -f "$BACKUP" && ! -L "$BACKUP" ]] || die "backup must be a regular non-symlink file."
BACKUP_MODE="$(stat -c '%a' "$BACKUP")"
(( (8#$BACKUP_MODE & 077) == 0 )) || die "backup must not be accessible by group or others."
BACKUP_SIZE="$(stat -c '%s' "$BACKUP")"
(( BACKUP_SIZE >= 128 )) || die "backup is implausibly small (${BACKUP_SIZE} bytes)."

[[ "$PASSPHRASE_FILE" == /* && "$PASSPHRASE_FILE" != "/" ]] || die "passphrase file must be a specific absolute path."
[[ -f "$PASSPHRASE_FILE" && ! -L "$PASSPHRASE_FILE" ]] || die "passphrase file must be a regular non-symlink file."
PASSPHRASE_MODE="$(stat -c '%a' "$PASSPHRASE_FILE")"
(( (8#$PASSPHRASE_MODE & 077) == 0 )) || die "passphrase file must not be accessible by group or others."
if ! awk 'NR == 1 { if (length($0) < 32) exit 1; next } { exit 1 } END { if (NR != 1) exit 1 }' "$PASSPHRASE_FILE"; then
    die "passphrase must be exactly one line of at least 32 characters."
fi

[[ "$MANIFEST" == /* && "$MANIFEST" != "/" ]] || die "manifest must be a specific absolute path."
MANIFEST_DIR="$(dirname -- "$MANIFEST")"
[[ -d "$MANIFEST_DIR" && ! -L "$MANIFEST_DIR" ]] || die "manifest parent must be an existing non-symlink directory."
[[ ! -e "$MANIFEST" && ! -L "$MANIFEST" ]] || die "refusing to overwrite manifest: $MANIFEST"
BACKUP_CANONICAL="$(readlink -f -- "$BACKUP")"
PASSPHRASE_CANONICAL="$(readlink -f -- "$PASSPHRASE_FILE")"
MANIFEST_CANONICAL="$(readlink -m -- "$MANIFEST")"
[[ "$MANIFEST_CANONICAL" != "$BACKUP_CANONICAL" && "$MANIFEST_CANONICAL" != "$PASSPHRASE_CANONICAL" ]] \
    || die "manifest path collides with an input file."

[[ "$IMAGE" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}$ ]] \
    || die "PostgreSQL image must be pinned by a lowercase sha256 digest."
if [[ ! "$READY_TIMEOUT" =~ ^[0-9]+$ ]] || (( READY_TIMEOUT < 5 || READY_TIMEOUT > 300 )); then
    die "RESTORE_DRILL_READY_TIMEOUT_SECONDS must be between 5 and 300."
fi

if [[ -z "$ENGINE" ]]; then
    for candidate in /usr/bin/docker /usr/local/bin/docker /usr/bin/podman /usr/local/bin/podman; do
        if [[ -x "$candidate" ]]; then
            ENGINE="$candidate"
            break
        fi
    done
fi
[[ -n "$ENGINE" && "$ENGINE" == /* && -x "$ENGINE" ]] || die "no trusted absolute Docker/Podman executable was found."
ENGINE="$(readlink -f -- "$ENGINE")"
case "$(basename -- "$ENGINE")" in
    docker|podman) ;;
    *) die "container engine must resolve to a docker or podman executable." ;;
esac
ENGINE_MODE="$(stat -c '%a' "$ENGINE")"
(( (8#$ENGINE_MODE & 022) == 0 )) || die "container engine must not be group/world writable."

for dependency in gpg gzip sha256sum python3; do
    command -v "$dependency" >/dev/null || die "required executable is missing: $dependency"
done
if ! "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1; then
    die "pinned PostgreSQL image is not present locally; pull the exact digest before the drill."
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swift-vapor-restore-drill.XXXXXX")"
GNUPGHOME="$WORK_DIR/gnupg"
mkdir -m 0700 "$GNUPGHOME"
CONTAINER_NAME="swift-vapor-restore-$PPID-$$-$RANDOM"
CONTAINER_STARTED=0
MANIFEST_TMP=""

cleanup() {
    set +e
    if (( CONTAINER_STARTED == 1 )); then
        "$ENGINE" rm --force "$CONTAINER_NAME" >/dev/null 2>&1
    fi
    [[ -z "$MANIFEST_TMP" ]] || rm -f -- "$MANIFEST_TMP"
    [[ ! -d "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

BACKUP_SHA="$(sha256sum -- "$BACKUP")"
BACKUP_SHA="${BACKUP_SHA%% *}"
[[ "$BACKUP_SHA" =~ ^[0-9a-f]{64}$ ]] || die "could not hash backup artifact."
BACKUP_MTIME="$(stat -c '%Y' "$BACKUP")"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
START_UNIX="$(date -u +%s)"

echo "restore-drill: starting isolated PostgreSQL container (network=none, no host mounts)."
"$ENGINE" run --detach --rm \
    --name "$CONTAINER_NAME" \
    --network none \
    --security-opt no-new-privileges:true \
    --pids-limit 256 \
    --memory 2g \
    --cpus 2 \
    --tmpfs /var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=2147483648 \
    --tmpfs /var/run/postgresql:rw,nosuid,nodev,noexec,size=16777216 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=67108864 \
    --env POSTGRES_DB=restore_drill \
    --env POSTGRES_USER=restore_drill \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
    "$IMAGE" \
    -c fsync=off -c synchronous_commit=off -c full_page_writes=off >/dev/null
CONTAINER_STARTED=1

READY_DEADLINE=$(( SECONDS + READY_TIMEOUT ))
until "$ENGINE" exec "$CONTAINER_NAME" pg_isready --quiet --username restore_drill --dbname restore_drill; do
    RUNNING="$("$ENGINE" inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)"
    [[ "$RUNNING" == "true" ]] || die "isolated PostgreSQL container exited before becoming ready."
    (( SECONDS < READY_DEADLINE )) || die "isolated PostgreSQL did not become ready within ${READY_TIMEOUT}s."
    sleep 1
done

echo "restore-drill: streaming authenticated decrypt -> decompress -> isolated psql."
if ! gpg --homedir "$GNUPGHOME" --no-options --batch --yes \
        --pinentry-mode loopback --no-symkey-cache \
        --passphrase-file "$PASSPHRASE_FILE" \
        --decrypt "$BACKUP" \
    | gzip --decompress --stdout \
    | "$ENGINE" exec --interactive "$CONTAINER_NAME" \
        psql --quiet --set ON_ERROR_STOP=1 --username restore_drill --dbname restore_drill \
        >/dev/null; then
    die "restore pipeline failed; no success manifest was published."
fi

BACKUP_SHA_AFTER="$(sha256sum -- "$BACKUP")"
BACKUP_SHA_AFTER="${BACKUP_SHA_AFTER%% *}"
[[ "$BACKUP_SHA_AFTER" == "$BACKUP_SHA" ]] || die "backup artifact changed during the drill."

psql_scalar() {
    "$ENGINE" exec "$CONTAINER_NAME" \
        psql --tuples-only --no-align --set ON_ERROR_STOP=1 \
        --username restore_drill --dbname restore_drill --command "$1"
}

TABLE_COUNT="$(psql_scalar "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';")"
DATABASE_SIZE="$(psql_scalar "SELECT pg_database_size(current_database());")"
POSTGRES_VERSION_NUM="$(psql_scalar "SHOW server_version_num;")"
if [[ ! "$TABLE_COUNT" =~ ^[0-9]+$ ]] || (( TABLE_COUNT == 0 )); then
    die "restored database contains no public base tables."
fi
if [[ ! "$DATABASE_SIZE" =~ ^[0-9]+$ ]] || (( DATABASE_SIZE == 0 )); then
    die "restored database size check failed."
fi
[[ "$POSTGRES_VERSION_NUM" =~ ^[0-9]{5,6}$ ]] || die "PostgreSQL version check failed."

LOGICAL_DUMP_SHA="$("$ENGINE" exec "$CONTAINER_NAME" \
    pg_dump --format=custom --no-owner --no-privileges \
    --username restore_drill --dbname restore_drill | sha256sum)"
LOGICAL_DUMP_SHA="${LOGICAL_DUMP_SHA%% *}"
[[ "$LOGICAL_DUMP_SHA" =~ ^[0-9a-f]{64}$ ]] || die "logical read-back verification failed."

# Dispose of the database before publishing success. A failed removal leaves no
# success manifest and the EXIT trap attempts removal once more.
"$ENGINE" rm --force "$CONTAINER_NAME" >/dev/null
CONTAINER_STARTED=0

COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMPLETED_UNIX="$(date -u +%s)"
DURATION_SECONDS=$(( COMPLETED_UNIX - START_UNIX ))
(( DURATION_SECONDS >= 0 )) || DURATION_SECONDS=0
ARTIFACT_AGE_SECONDS=$(( COMPLETED_UNIX - BACKUP_MTIME ))
(( ARTIFACT_AGE_SECONDS >= 0 )) || ARTIFACT_AGE_SECONDS=0
BACKUP_BASENAME="$(basename -- "$BACKUP")"
ENGINE_NAME="$(basename -- "$ENGINE")"
SCRIPT_SHA="$(sha256sum -- "${BASH_SOURCE[0]}")"
SCRIPT_SHA="${SCRIPT_SHA%% *}"
SOURCE_REVISION="unknown"
REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v git >/dev/null && git -C "$REPOSITORY_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SOURCE_REVISION="$(git -C "$REPOSITORY_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"
fi

MANIFEST_TMP="$(mktemp --tmpdir="$MANIFEST_DIR" ".$(basename -- "$MANIFEST").partial.XXXXXX")"
python3 - "$BACKUP_BASENAME" "$BACKUP_SHA" "$BACKUP_SIZE" "$BACKUP_MTIME" \
    "$IMAGE" "$ENGINE_NAME" "$POSTGRES_VERSION_NUM" "$TABLE_COUNT" \
    "$DATABASE_SIZE" "$LOGICAL_DUMP_SHA" "$STARTED_AT" "$COMPLETED_AT" \
    "$DURATION_SECONDS" "$ARTIFACT_AGE_SECONDS" "$SOURCE_REVISION" "$SCRIPT_SHA" \
    > "$MANIFEST_TMP" <<'PY'
import json
import sys

(
    backup_name, backup_sha, backup_size, backup_mtime, image, engine,
    postgres_version, table_count, database_size, logical_dump_sha,
    started_at, completed_at, duration_seconds, artifact_age_seconds,
    source_revision, script_sha,
) = sys.argv[1:]

manifest = {
    "schema_version": 1,
    "status": "succeeded",
    "started_at": started_at,
    "completed_at": completed_at,
    "duration_seconds": int(duration_seconds),
    "backup": {
        "filename": backup_name,
        "sha256": backup_sha,
        "size_bytes": int(backup_size),
        "mtime_unix": int(backup_mtime),
        "artifact_age_seconds_at_completion": int(artifact_age_seconds),
        "preserved": True,
    },
    "restore": {
        "database": "restore_drill",
        "postgres_image": image,
        "postgres_server_version_num": int(postgres_version),
        "public_base_table_count": int(table_count),
        "database_size_bytes": int(database_size),
        "logical_readback_sha256": logical_dump_sha,
        "database_disposed_before_success": True,
    },
    "isolation": {
        "container_engine": engine,
        "network": "none",
        "host_mounts": False,
        "plaintext_dump_written_to_host": False,
    },
    "tool": {
        "source_revision": source_revision,
        "script_sha256": script_sha,
    },
}
json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
chmod 0600 "$MANIFEST_TMP"
# A hard link is an atomic no-clobber publish because the temporary file lives
# in the manifest directory. Never replace prior recovery evidence.
ln -- "$MANIFEST_TMP" "$MANIFEST" || die "manifest appeared concurrently; refusing to overwrite it."
rm -f -- "$MANIFEST_TMP"
MANIFEST_TMP=""

echo "restore-drill: success (${TABLE_COUNT} tables, ${DATABASE_SIZE} bytes, ${DURATION_SECONDS}s); manifest: $MANIFEST"
