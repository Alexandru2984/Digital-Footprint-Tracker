#!/usr/bin/env bash

# Forced-command production deploy. Builds origin/main in isolation, requires a
# recent verified encrypted backup, migrates through a dedicated oneshot unit,
# switches one immutable release symlink, and automatically restores the prior
# backend/frontend/CSP if post-switch verification fails.

set -Eeuo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 022

REPOSITORY="${SWIFT_VAPOR_REPOSITORY:-/var/lib/swift-deploy/repository}"
RELEASE_ROOT=/srv/swift-vapor/releases
CURRENT_LINK=/srv/swift-vapor/current
NEXT_LINK=/srv/swift-vapor/next
LOCK_FILE=/srv/swift-vapor/deploy.lock
READINESS_URL=http://127.0.0.1:8085/ready
STATIC_URL=http://127.0.0.1:8110/index.html
ONION_HOST=5jyd4lflkewyc3gm42uxvi2aryh5g2l4ib2pm5uewpff3ld7yfii5iid.onion
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_RELEASE="$SCRIPT_DIR/build-release.sh"
PREFLIGHT="$SCRIPT_DIR/production-preflight.sh"
# shellcheck source=scripts/release-lib.sh
source "$SCRIPT_DIR/release-lib.sh"

WORK=""
PREVIOUS=""
RELEASE=""
CANDIDATE_SOURCE=""
CURRENT_SWITCHED=0
CSP_TRANSITIONED=0
NEXT_SWITCHED=0
SUCCESS=0

cleanup_work() {
    if [[ -n "$WORK" && "$WORK" == "$RELEASE_ROOT"/.deploy-* && -d "$WORK" ]]; then
        chmod -R u+w -- "$WORK" 2>/dev/null || true
        rm -rf -- "$WORK"
    fi
    if (( NEXT_SWITCHED )) && [[ -L "$NEXT_LINK" ]] \
        && [[ "$(readlink -f -- "$NEXT_LINK")" == "$RELEASE" ]]; then
        rm -f -- "$NEXT_LINK"
    fi
}

wait_for_readiness() {
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if curl --fail --silent --show-error --max-time 2 "$READINESS_URL" >/dev/null; then
            echo "[deploy] backend ready after ${attempt}s"
            return 0
        fi
        sleep 1
    done
    echo "[deploy] backend readiness check failed" >&2
    return 1
}

verify_served_frontend() {
    local expected actual
    expected="$(release_manifest_value "$1" frontend_index_sha256)"
    actual="$(curl --fail --silent --show-error --max-time 5 \
        --header "Host: $ONION_HOST" "$STATIC_URL" | sha256sum | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || {
        echo "[deploy] nginx served frontend hash $actual, expected $expected" >&2
        return 1
    }
    echo "[deploy] nginx is serving the selected frontend"
}

rollback() {
    local rollback_failed=0
    set +e
    echo "[deploy] failure detected; starting automatic rollback" >&2
    if (( CURRENT_SWITCHED )) && [[ -n "$PREVIOUS" ]]; then
        switch_release_link "$PREVIOUS" "$CURRENT_LINK" "$RELEASE_ROOT" || rollback_failed=1
        sudo -n /bin/systemctl restart swift-vapor.service || rollback_failed=1
        wait_for_readiness || rollback_failed=1
        verify_served_frontend "$PREVIOUS" || rollback_failed=1
    fi
    if (( CSP_TRANSITIONED )) && [[ -n "$PREVIOUS" && -n "$CANDIDATE_SOURCE" ]]; then
        "$CANDIDATE_SOURCE/scripts/update-csp-hashes.sh" "$PREVIOUS/frontend" || rollback_failed=1
    fi
    if (( rollback_failed )); then
        echo "[deploy] ROLLBACK INCOMPLETE: operator intervention required" >&2
    else
        echo "[deploy] previous release restored; database migrations were not reverted" >&2
    fi
}

finish() {
    local status=$?
    trap - EXIT INT TERM
    if (( status != 0 && ! SUCCESS )); then rollback; fi
    cleanup_work
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT TERM

[[ -d "$REPOSITORY/.git" ]] || { echo "[deploy] repository missing" >&2; exit 1; }
mkdir -p "$RELEASE_ROOT"
chmod 0755 "$RELEASE_ROOT"
exec 9>"$LOCK_FILE"
chmod 0600 "$LOCK_FILE"
flock -n 9 || { echo "[deploy] another deployment is running" >&2; exit 1; }

[[ -x "$PREFLIGHT" ]] || { echo "[deploy] root-installed preflight is missing" >&2; exit 1; }
echo "[deploy] enforcing production acceptance preflight"
"$PREFLIGHT" --deployment-gate --repository "$REPOSITORY"

if [[ -n "$(git -C "$REPOSITORY" status --porcelain)" ]]; then
    echo "[deploy] repository has local changes; refusing to overwrite operator work" >&2
    exit 1
fi

echo "[deploy] fetching origin/main"
git -C "$REPOSITORY" fetch --quiet --no-tags origin main
LOCAL="$(git -C "$REPOSITORY" rev-parse HEAD)"
REMOTE="$(git -C "$REPOSITORY" rev-parse origin/main)"
[[ "$LOCAL" =~ ^[0-9a-f]{40}$ && "$REMOTE" =~ ^[0-9a-f]{40}$ ]] || {
    echo "[deploy] invalid Git commit identity" >&2
    exit 1
}
git -C "$REPOSITORY" merge-base --is-ancestor "$LOCAL" "$REMOTE" || {
    echo "[deploy] local main diverged from origin/main" >&2
    exit 1
}

[[ -L "$CURRENT_LINK" ]] || {
    echo "[deploy] atomic layout is not bootstrapped: $CURRENT_LINK is not a symlink" >&2
    exit 1
}
PREVIOUS="$(readlink -f -- "$CURRENT_LINK")"
verify_release "$PREVIOUS" "$RELEASE_ROOT" || {
    echo "[deploy] current release failed integrity verification: $PREVIOUS" >&2
    exit 1
}
systemctl cat swift-vapor.service | grep -qF "$CURRENT_LINK/Run" || {
    echo "[deploy] installed application unit does not use the atomic release link" >&2
    exit 1
}
systemctl cat swift-vapor-migrate.service | grep -qF "$NEXT_LINK/Run" || {
    echo "[deploy] explicit migration unit is not installed" >&2
    exit 1
}
[[ -x /usr/local/sbin/update-swift-csp ]] || {
    echo "[deploy] restricted CSP installer is not installed" >&2
    exit 1
}

if [[ "$(release_manifest_value "$PREVIOUS" commit)" == "$REMOTE" ]]; then
    echo "[deploy] release $REMOTE is already active"
    if [[ "$LOCAL" != "$REMOTE" ]]; then git -C "$REPOSITORY" merge --ff-only "$REMOTE"; fi
    SUCCESS=1
    exit 0
fi

echo "[deploy] enforcing recent verified-backup gate"
"$REPOSITORY/scripts/check-backup.sh" \
    --directory /var/lib/swift-vapor-backup/artifacts \
    --status-file /var/lib/swift-vapor-backup/status/last-success \
    --max-age-hours 30

echo "[deploy] building immutable release $REMOTE"
"$BUILD_RELEASE" "$REMOTE" >/dev/null
RELEASE="$RELEASE_ROOT/$REMOTE"
verify_release "$RELEASE" "$RELEASE_ROOT" || { echo "[deploy] candidate verification failed" >&2; exit 1; }

# Export candidate deployment helpers independently of the mutable checkout so
# rollback still has them even after the repository fast-forwards.
WORK="$(mktemp -d --tmpdir="$RELEASE_ROOT" ".deploy-${REMOTE:0:12}.XXXXXX")"
CANDIDATE_SOURCE="$WORK/source"
mkdir -p "$CANDIDATE_SOURCE"
git -C "$REPOSITORY" archive --format=tar "$REMOTE" | tar -xf - -C "$CANDIDATE_SOURCE"

echo "[deploy] running explicit migration gate"
switch_release_link "$RELEASE" "$NEXT_LINK" "$RELEASE_ROOT"
NEXT_SWITCHED=1
sudo -n /bin/systemctl start swift-vapor-migrate.service

# nginx first accepts both generations of inline-script hashes. This removes
# the otherwise unavoidable window where either the old or new SPA is blocked.
echo "[deploy] installing transition CSP"
"$CANDIDATE_SOURCE/scripts/update-csp-hashes.sh" "$RELEASE/frontend" "$PREVIOUS/frontend"
CSP_TRANSITIONED=1

OLD_PID="$(systemctl show --property MainPID --value swift-vapor.service)"
echo "[deploy] atomically selecting $REMOTE"
switch_release_link "$RELEASE" "$CURRENT_LINK" "$RELEASE_ROOT"
CURRENT_SWITCHED=1
sudo -n /bin/systemctl restart swift-vapor.service
wait_for_readiness
NEW_PID="$(systemctl show --property MainPID --value swift-vapor.service)"
[[ "$NEW_PID" =~ ^[1-9][0-9]*$ && "$NEW_PID" != "$OLD_PID" ]] || {
    echo "[deploy] service did not acquire a new main process" >&2
    exit 1
}
verify_served_frontend "$RELEASE"

echo "[deploy] narrowing CSP to the selected release"
"$CANDIDATE_SOURCE/scripts/update-csp-hashes.sh" "$RELEASE/frontend"

# Source checkout is metadata/tooling only now; neither nginx nor systemd serves
# from it, so the fast-forward cannot expose a half-built frontend.
if [[ "$LOCAL" != "$REMOTE" ]]; then
    git -C "$REPOSITORY" merge --ff-only "$REMOTE"
fi

SUCCESS=1
echo "[deploy] release $REMOTE deployed and verified"
