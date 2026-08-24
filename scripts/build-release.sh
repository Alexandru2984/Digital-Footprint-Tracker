#!/usr/bin/env bash

# Build one immutable backend + frontend bundle from a committed Git object.
# The source is exported with git archive, so dirty working-tree files and the
# live frontend can never leak into a release.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

REPOSITORY="${SWIFT_VAPOR_REPOSITORY:-/var/lib/swift-deploy/repository}"
RELEASE_ROOT="/srv/swift-vapor/releases"
REVISION="${1:-HEAD}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release-lib.sh
source "$SCRIPT_DIR/release-lib.sh"

[[ -d "$REPOSITORY/.git" ]] || { echo "release: repository missing: $REPOSITORY" >&2; exit 1; }
[[ "$RELEASE_ROOT" == /* && "$RELEASE_ROOT" != "/" ]] || { echo "release: unsafe root" >&2; exit 1; }

COMMIT="$(git -C "$REPOSITORY" rev-parse --verify "${REVISION}^{commit}")"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "release: revision is not a full commit ID" >&2; exit 1; }
RELEASE="$RELEASE_ROOT/$COMMIT"

mkdir -p "$RELEASE_ROOT"
chmod 0755 "$RELEASE_ROOT"
if [[ -e "$RELEASE" ]]; then
    verify_release "$RELEASE" "$RELEASE_ROOT" || {
        echo "release: existing bundle failed integrity verification: $RELEASE" >&2
        exit 1
    }
    echo "release: verified existing $COMMIT" >&2
    printf '%s\n' "$RELEASE"
    exit 0
fi

WORK="$(mktemp -d --tmpdir="$RELEASE_ROOT" ".build-${COMMIT:0:12}.XXXXXX")"
cleanup() {
    [[ "$WORK" == "$RELEASE_ROOT"/.build-* && -d "$WORK" ]] || return 0
    chmod -R u+w -- "$WORK" 2>/dev/null || true
    rm -rf -- "$WORK"
}
trap cleanup EXIT

SOURCE="$WORK/source"
SCRATCH="$WORK/build"
BUNDLE="$WORK/bundle"
mkdir -p "$SOURCE" "$BUNDLE/frontend" "$BUNDLE/scripts"

echo "release: exporting $COMMIT" >&2
git -C "$REPOSITORY" archive --format=tar "$COMMIT" | tar -xf - -C "$SOURCE"

echo "release: validating frontend" >&2
npm --prefix "$SOURCE/frontend" test >&2

echo "release: building Swift release" >&2
# swift-deploy's home (/var/lib/swift-deploy) is root-owned by design (see
# ops/tmpfiles.d/swift-vapor.conf) so a compromised build can't drop a login
# key into .ssh. SwiftPM still needs somewhere writable for its manifest and
# module cache, so point it at this build's own ephemeral workspace instead of
# $HOME/.cache — cleaned up by the existing trap along with everything else.
export XDG_CACHE_HOME="$WORK/cache"
export XDG_CONFIG_HOME="$WORK/config"
mkdir -p "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME"
swift build --package-path "$SOURCE" --scratch-path "$SCRATCH" -c release >&2
BIN_PATH="$(swift build --package-path "$SOURCE" --scratch-path "$SCRATCH" -c release --show-bin-path)"

install -m 0555 "$BIN_PATH/Run" "$BUNDLE/Run"
RESOURCE="$BIN_PATH/DigitalFootprintTracker_App.resources"
[[ -d "$RESOURCE" ]] || { echo "release: Swift resource bundle missing" >&2; exit 1; }
rsync -a --chmod=D0555,F0444 "$RESOURCE/" "$BUNDLE/DigitalFootprintTracker_App.resources/"

# Only runtime assets enter the served tree. Build tooling, lockfiles and
# node_modules stay outside the release and outside nginx's document root.
rsync -a --chmod=D0555,F0444 \
    --exclude='/node_modules/' \
    --exclude='/package.json' \
    --exclude='/package-lock.json' \
    --exclude='/check.mjs' \
    --exclude='/input.css' \
    --exclude='/tailwind.config.js' \
    "$SOURCE/frontend/" "$BUNDLE/frontend/"
install -m 0555 "$SOURCE/scripts/generate_report.py" "$BUNDLE/scripts/generate_report.py"

[[ -z "$(find "$BUNDLE" -type l -print -quit)" ]] || {
    echo "release: symlinks are forbidden inside release bundles" >&2
    exit 1
}

RUN_HASH="$(sha256sum "$BUNDLE/Run" | awk '{print $1}')"
FRONTEND_HASH="$(sha256sum "$BUNDLE/frontend/index.html" | awk '{print $1}')"
(cd "$BUNDLE" && find . -type f ! -path './SHA256SUMS' ! -path './RELEASE' -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS)
FILES_HASH="$(sha256sum "$BUNDLE/SHA256SUMS" | awk '{print $1}')"
{
    printf 'commit=%s\n' "$COMMIT"
    printf 'run_sha256=%s\n' "$RUN_HASH"
    printf 'frontend_index_sha256=%s\n' "$FRONTEND_HASH"
    printf 'files_manifest_sha256=%s\n' "$FILES_HASH"
    printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$BUNDLE/RELEASE"
chmod 0444 "$BUNDLE/RELEASE"

# -mindepth 1 leaves $BUNDLE itself writable for now: renaming a directory
# into a new parent requires write permission on the directory being moved
# (the kernel has to update its own ".." entry), so locking it down here would
# make the mv below fail with EACCES. It gets chmod'd immutable right after.
find "$BUNDLE" -mindepth 1 -type d -exec chmod 0555 {} +
find "$BUNDLE" -mindepth 1 -type f ! -path "$BUNDLE/Run" ! -path "$BUNDLE/scripts/generate_report.py" \
    -exec chmod 0444 {} +

# The final rename is same-filesystem and atomic. Validate again at its canonical
# commit-named path, where the path constraints in verify_release apply.
mv -- "$BUNDLE" "$RELEASE"
chmod 0555 "$RELEASE"
if ! verify_release "$RELEASE" "$RELEASE_ROOT"; then
    echo "release: published bundle failed integrity verification" >&2
    chmod -R u+w -- "$RELEASE" 2>/dev/null || true
    rm -rf -- "$RELEASE"
    exit 1
fi

echo "release: published $RELEASE" >&2
printf '%s\n' "$RELEASE"
