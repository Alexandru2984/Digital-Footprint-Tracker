#!/usr/bin/env bash

set -euo pipefail

# The release used to name the build tooling it wanted to keep out, so each new
# tool shipped by default — sri.mjs, playwright.config.mjs, the audit allowlist
# and the browser specs were all served from the public document root. The
# filter is an allowlist now, and what this test really checks is the default:
# a file nobody listed must not reach the served tree.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FILTER="$ROOT/ops/release-frontend.filter"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

fail() { echo "release filter contract: $1" >&2; exit 1; }

[[ -r "$FILTER" ]] || fail "missing $FILTER"
builder="$ROOT/scripts/build-release.sh"
grep -q 'release-frontend.filter' "$builder" || fail "build-release.sh must use the shared filter"
grep -q -- '--prune-empty-dirs' "$builder" \
    || fail "build-release.sh must prune empty directories, or unlisted ones appear in the tree"
grep -qE '^\s*-\s+\*\s*$' "$FILTER" || fail "the filter must end by excluding everything unnamed"

# A copy of the real frontend, plus tooling that does not exist yet.
rsync -a --exclude=node_modules "$ROOT/frontend/" "$TMP/source/"
printf '// invented by a future contributor\n' > "$TMP/source/fixture-tool.mjs"
printf '{"note":"not a runtime asset"}\n' > "$TMP/source/fixture-notes.json"
mkdir -p "$TMP/source/fixtures" && printf 'x\n' > "$TMP/source/fixtures/sample.txt"

# The same two options the release uses, asserted below so they stay together.
rsync -a --filter=". $FILTER" --prune-empty-dirs "$TMP/source/" "$TMP/release/"

# What the site actually needs.
for want in index.html admin.html tailwind.css admin.js investigation.js dark-web.js \
            favicon.svg manifest.json robots.txt sitemap.xml openapi.yaml; do
    [[ -f "$TMP/release/$want" ]] || fail "expected $want in the release"
done
[[ -f "$TMP/release/docs/openapi.yaml" || -d "$TMP/release/docs" ]] || fail "expected the docs directory in the release"

# Build and test tooling, including the kind nobody has written yet.
for unwanted in sri.mjs check.mjs build-css.mjs input.css package.json package-lock.json \
                playwright.config.mjs fixture-tool.mjs fixture-notes.json npm-audit-allowlist.json \
                osv-scanner.toml tailwind.config.js; do
    [[ ! -e "$TMP/release/$unwanted" ]] || fail "$unwanted must not reach the served tree"
done
[[ ! -e "$TMP/release/tests" ]] || fail "browser specs must not reach the served tree"
[[ ! -e "$TMP/release/node_modules" ]] || fail "node_modules must not reach the served tree"
[[ ! -e "$TMP/release/fixtures" ]] || fail "an unlisted directory must not reach the served tree"

# And no stray .mjs anywhere in the tree, whatever its name.
stray="$(find "$TMP/release" -name '*.mjs' -print -quit)"
[[ -z "$stray" ]] || fail "tooling slipped in: $stray"

echo "release frontend filter contract tests passed"
