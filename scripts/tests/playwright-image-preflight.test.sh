#!/usr/bin/env bash

set -euo pipefail

# The preflight exists because a dependabot bump moved @playwright/test without
# the image and every browser test failed with a launch error that named
# neither. Hermetic: a fake playwright-core and a fake browsers directory.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFLIGHT="$ROOT/scripts/playwright-image-preflight.mjs"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

fail() { echo "playwright-image-preflight contract: $1" >&2; exit 1; }

core="$TMP/frontend/node_modules/playwright-core"
mkdir -p "$core"
printf '{"version":"9.9.9"}\n' > "$core/package.json"
printf '{"browsers":[{"name":"chromium","revision":"4242"},{"name":"chromium-headless-shell","revision":"4242"}]}\n' \
    > "$core/browsers.json"

# The pairing that works.
mkdir -p "$TMP/matching/chromium_headless_shell-4242"
node "$PREFLIGHT" "$TMP/frontend" "$TMP/matching" >/dev/null \
    || fail "expected a matching image to pass"

# The pairing that broke CI: the package moved, the image did not.
mkdir -p "$TMP/stale/chromium_headless_shell-4241"
if node "$PREFLIGHT" "$TMP/frontend" "$TMP/stale" 2>"$TMP/stale.err"; then
    fail "expected a stale image to be refused"
fi
grep -q "needs chromium_headless_shell-4242" "$TMP/stale.err" || fail "expected the needed build to be named"
grep -q "carries chromium_headless_shell-4241" "$TMP/stale.err" || fail "expected the present build to be named"
grep -q "playwright:v9.9.9-noble" "$TMP/stale.err" || fail "expected the image to pin to be named"

# The runner must check before it tests, not after.
runner="$ROOT/scripts/run-browser-tests.sh"
preflight_line="$(grep -n 'playwright-image-preflight.mjs' "$runner" | head -1 | cut -d: -f1)"
tests_line="$(grep -n 'playwright test' "$runner" | head -1 | cut -d: -f1)"
[[ -n "$preflight_line" && -n "$tests_line" ]] || fail "expected the runner to call the preflight and the tests"
(( preflight_line < tests_line )) || fail "the preflight must run before the tests"

echo "playwright image preflight contract tests passed"
