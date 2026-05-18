#!/usr/bin/env bash
#
# CI deploy entrypoint. Triggered over SSH by the deploy job in
# .github/workflows/ci.yml. The authorized_keys entry for the deploy
# keypair has `command="/home/micu/swift+vapor/scripts/deploy.sh"` so
# this script is the ONLY thing that key can run — the action's `script:`
# block is ignored by sshd in favour of this file.
#
# Pipeline:
#   1. Fast-forward main from origin (refuses if local commits diverged).
#   2. Build release binary.
#   3. Restart systemd unit via passwordless sudo rule for that one verb.
#
# Steps run sequentially with `set -e` — a build failure aborts before
# the restart, so a broken commit cannot brick the running service.
#
# Logged to stderr so GitHub Actions surfaces each phase in the job log.

set -euo pipefail

cd /home/micu/swift+vapor

echo "[deploy] fetching origin/main"
git fetch --quiet origin main

LOCAL="$(git rev-parse HEAD)"
REMOTE="$(git rev-parse origin/main)"
if [[ "$LOCAL" == "$REMOTE" ]]; then
    echo "[deploy] already at $REMOTE — nothing to deploy"
    exit 0
fi

echo "[deploy] fast-forwarding $LOCAL -> $REMOTE"
git merge --ff-only origin/main

echo "[deploy] building release binary"
swift build -c release

echo "[deploy] restarting swift-vapor.service"
sudo /bin/systemctl restart swift-vapor.service

# Brief healthcheck so a deploy that produces a non-listening binary is
# surfaced in the action's log rather than only when the next user
# request 502s.
echo "[deploy] waiting for healthcheck"
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS --max-time 2 http://127.0.0.1:8085/health > /dev/null; then
        echo "[deploy] healthy after ${i}s"
        exit 0
    fi
    sleep 1
done
echo "[deploy] healthcheck did not pass within 10s — investigate" >&2
exit 1
