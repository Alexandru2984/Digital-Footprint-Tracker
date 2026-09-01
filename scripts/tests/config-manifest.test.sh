#!/usr/bin/env bash

set -euo pipefail

# --accept-path exists so the sanctioned writer of one pinned file can adopt its
# own change. That is only safe if it stays narrow, so the contract worth
# testing is mostly what it refuses: a path the globs do not cover, a file the
# baseline has never seen, and — the one that matters most — drift anywhere
# else, which must survive the re-pin untouched.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

ETC="$TMP/etc"
LIB="$TMP/lib"
mkdir -p "$ETC" "$LIB"
printf 'csp original\n' > "$ETC/swift-csp.conf"
printf 'headers original\n' > "$ETC/swift-proxy-headers.conf"
printf 'helper original\n' > "$LIB/update-swift-csp"
chmod 0644 "$ETC"/*.conf
chmod 0755 "$LIB/update-swift-csp"

manifest() {
    CONFIG_MANIFEST_PATH="$TMP/state/manifest.json" \
    CONFIG_MANIFEST_RELEASE_LINK="$TMP/current" \
    CONFIG_MANIFEST_GLOBS="$ETC/*.conf $LIB/*" \
    "$ROOT/scripts/config-manifest.sh" "$@"
}

MANIFEST="$TMP/state/manifest.json"

fail() { echo "config-manifest contract: $1" >&2; exit 1; }

# Without a baseline there is nothing to re-pin, and saying so beats writing one.
manifest --accept-path "$ETC/swift-csp.conf" >/dev/null 2>&1 \
    && fail "expected --accept-path to refuse when no baseline exists"

manifest --accept >/dev/null
manifest --verify >/dev/null

# A relative path is rejected before anything is read.
manifest --accept-path etc/swift-csp.conf >/dev/null 2>&1 \
    && fail "expected a relative path to be refused"

# Re-pinning an unchanged file is a no-op, not an error: the deploy calls this
# unconditionally and a clean run must not look like a failure.
manifest --accept-path "$ETC/swift-csp.conf" | grep -q 'already matches' \
    || fail "expected an unchanged file to report nothing to re-pin"

# The core case: the file its writer is allowed to change.
before="$(sha256sum "$MANIFEST" | cut -d' ' -f1)"
printf 'csp rewritten by a deploy\n' > "$ETC/swift-csp.conf"
manifest --verify >/dev/null 2>&1 && fail "expected a rewritten file to register as drift"
manifest --accept-path "$ETC/swift-csp.conf" >/dev/null
manifest --verify >/dev/null || fail "expected the re-pin to clear that file's drift"
[[ "$(sha256sum "$MANIFEST" | cut -d' ' -f1)" != "$before" ]] \
    || fail "expected the manifest to change"

# Mode is part of the record, so a permission-only change is drift the writer
# can also adopt for its own file.
chmod 0640 "$ETC/swift-csp.conf"
manifest --verify >/dev/null 2>&1 && fail "expected a mode change to register as drift"
manifest --accept-path "$ETC/swift-csp.conf" >/dev/null
manifest --verify >/dev/null || fail "expected the re-pin to adopt the new mode"

# The property this whole design rests on: accepting one file must not quietly
# absorb anyone else's change. Two files drift, one is sanctioned, the other
# must still be reported — by name.
printf 'csp rewritten again\n' > "$ETC/swift-csp.conf"
printf 'headers edited by hand during an incident\n' > "$ETC/swift-proxy-headers.conf"
manifest --accept-path "$ETC/swift-csp.conf" >/dev/null
report="$(manifest --verify 2>&1)" && fail "expected the unrelated edit to still be drift"
grep -q "modified: $ETC/swift-proxy-headers.conf" <<<"$report" \
    || fail "expected the unrelated edit to be named in the report"
grep -q "swift-csp.conf" <<<"$report" \
    && fail "expected the re-pinned file to be absent from the report"
manifest --accept >/dev/null

# A path outside the globs can never be admitted, whatever it is.
printf 'not ours\n' > "$TMP/outside.conf"
manifest --accept-path "$TMP/outside.conf" >/dev/null 2>&1 \
    && fail "expected a path outside the pinned globs to be refused"

# A file the globs *do* cover but the baseline has never recorded is a new
# pinned file — a human decision, so it stays "added" drift until --accept.
printf 'brand new\n' > "$ETC/swift-extra.conf"
chmod 0644 "$ETC/swift-extra.conf"
manifest --accept-path "$ETC/swift-extra.conf" >/dev/null 2>&1 \
    && fail "expected an unbaselined file to be refused"
manifest --verify >/dev/null 2>&1 && fail "expected the new file to still register as drift"

# Every refusal above must have left the baseline exactly as it was.
python3 - "$MANIFEST" <<'PY'
import json, sys
entries = json.load(open(sys.argv[1]))["entries"]
paths = [entry["path"] for entry in entries]
assert len(paths) == 3, paths
assert paths == sorted(paths), paths
assert not any(path.endswith("swift-extra.conf") for path in paths), paths
assert not any(path.endswith("outside.conf") for path in paths), paths
PY

echo "config-manifest contract tests passed"
