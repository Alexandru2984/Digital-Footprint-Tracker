#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/release-lib.sh
source "$ROOT_DIR/scripts/release-lib.sh"

BASE="$(mktemp -d)"
cleanup() {
    chmod -R u+w -- "$BASE" 2>/dev/null || true
    rm -rf -- "$BASE"
}
trap cleanup EXIT

RELEASE_ROOT="$BASE/releases"
COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RELEASE="$RELEASE_ROOT/$COMMIT"
mkdir -p "$RELEASE/frontend" "$RELEASE/scripts" \
    "$RELEASE/DigitalFootprintTracker_App.resources"
printf 'binary\n' > "$RELEASE/Run"
printf '<!doctype html>\n' > "$RELEASE/frontend/index.html"
printf '#!/usr/bin/env python3\n' > "$RELEASE/scripts/generate_report.py"
printf '{}\n' > "$RELEASE/DigitalFootprintTracker_App.resources/sherlock_data.json"
chmod 0555 "$RELEASE/Run" "$RELEASE/scripts/generate_report.py"
RUN_HASH="$(sha256sum "$RELEASE/Run" | awk '{print $1}')"
FRONTEND_HASH="$(sha256sum "$RELEASE/frontend/index.html" | awk '{print $1}')"
(cd "$RELEASE" && find . -type f ! -path './SHA256SUMS' ! -path './RELEASE' -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS)
FILES_HASH="$(sha256sum "$RELEASE/SHA256SUMS" | awk '{print $1}')"
{
    printf 'commit=%s\n' "$COMMIT"
    printf 'run_sha256=%s\n' "$RUN_HASH"
    printf 'frontend_index_sha256=%s\n' "$FRONTEND_HASH"
    printf 'files_manifest_sha256=%s\n' "$FILES_HASH"
    printf 'created_at=2026-08-12T00:00:00Z\n'
} > "$RELEASE/RELEASE"
find "$RELEASE" -type d -exec chmod 0555 {} +
find "$RELEASE" -type f ! -path "$RELEASE/Run" ! -path "$RELEASE/scripts/generate_report.py" \
    -exec chmod 0444 {} +

verify_release "$RELEASE" "$RELEASE_ROOT"
switch_release_link "$RELEASE" "$BASE/current" "$RELEASE_ROOT"
[[ "$(readlink -f "$BASE/current")" == "$RELEASE" ]]

chmod u+w "$RELEASE/frontend/index.html"
printf 'tampered\n' >> "$RELEASE/frontend/index.html"
chmod 0444 "$RELEASE/frontend/index.html"
if verify_release "$RELEASE" "$RELEASE_ROOT"; then
    echo "expected modified frontend to fail manifest verification" >&2
    exit 1
fi

echo "release helper tests passed"
