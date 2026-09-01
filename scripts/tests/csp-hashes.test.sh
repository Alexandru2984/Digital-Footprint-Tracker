#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COLLECTOR="$ROOT_DIR/scripts/csp-hashes.mjs"
CSP="$ROOT_DIR/ops/nginx/snippets/swift-csp.conf"
INSTALLER="$ROOT_DIR/ops/libexec/update-swift-csp"
BASE="$(mktemp -d)"
cleanup() { rm -rf -- "$BASE"; }
trap cleanup EXIT

mapfile -t current < <(node "$COLLECTOR" "$ROOT_DIR/frontend")
(( ${#current[@]} >= 4 ))
mapfile -t duplicate < <(node "$COLLECTOR" "$ROOT_DIR/frontend" "$ROOT_DIR/frontend")
[[ "${current[*]}" == "${duplicate[*]}" ]]

cp -a "$ROOT_DIR/frontend" "$BASE/candidate"
printf '<script>window.__cspTransitionTest = true;</script>\n' >> "$BASE/candidate/index.html"
mapfile -t transition < <(node "$COLLECTOR" "$ROOT_DIR/frontend" "$BASE/candidate")
(( ${#transition[@]} == ${#current[@]} + 1 ))
for hash in "${current[@]}"; do
    printf '%s\n' "${transition[@]}" | grep -qFx "$hash"
done

grep -qF "script-src 'self' 'nonce-\$request_id'" "$CSP"
grep -qF "nonce-\\\$request_id" "$INSTALLER"
script_sources="$(sed -n "s/.*script-src \([^;]*\);.*/\1/p" "$CSP")"
[[ -n "$script_sources" && "$script_sources" != *"'unsafe-inline'"* ]]

# The installer is the sanctioned writer of a file config-manifest.sh pins, so
# it has to adopt its own change; drop that and the drift gate is permanently
# red after every deploy, which trains everyone to ignore it. Static check —
# the installer needs root to actually run — but it catches the edit that
# quietly removes the call.
# The single quotes are the point: this matches the installer's source text,
# it is not an expansion.
# shellcheck disable=SC2016
grep -qF -- '--accept-path "$CSP"' "$INSTALLER"
sed -n '/^if nginx -t && systemctl reload nginx.service; then$/,/^fi$/p' "$INSTALLER" \
    | grep -qFx '    repin_csp'

echo "CSP hash transition tests passed"
