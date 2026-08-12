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

echo "CSP hash transition tests passed"
