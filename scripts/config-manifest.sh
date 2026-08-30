#!/usr/bin/env bash

# Records and verifies the checksums of the host configuration this service
# depends on, so an out-of-band edit is visible instead of silent.
#
# The `current` symlink already binds the *release* to a commit SHA, and the
# preflight verifies it. Nothing covered the other half: the systemd units,
# nginx vhosts, CSP snippet, environment files and installed helpers that live
# under /etc and /usr/local and are edited by hand during incidents. This closes
# that gap — it is exactly the drift that accumulates when a live config is
# patched under pressure and the repository copy is never updated to match.
#
#   --accept   record the current state as the accepted baseline
#   --verify   compare the live state against the baseline (exit 1 on drift)
#   --print    write the manifest that would be accepted to stdout, change
#              nothing
#
# Mode and ownership are part of the record: a file made group-writable is drift
# even when its bytes are untouched.
#
# Deliberately out of scope: /etc/nginx/conf.d/cloudflare-*.conf, which a
# reviewed script regenerates from the official upstream ranges, and TLS
# certificates, which renew on their own. Pinning either would turn routine
# maintenance into a permanent false alarm; their integrity belongs to the
# process that writes them.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

MANIFEST="${CONFIG_MANIFEST_PATH:-/var/lib/swift-vapor-config/manifest.json}"
CURRENT_LINK="${CONFIG_MANIFEST_RELEASE_LINK:-/srv/swift-vapor/current}"

# Every pinned path. Globs are expanded here, so a *new* file appearing in one
# of these directories registers as drift too — which is the point: an extra
# systemd drop-in is as much a change as an edited one.
PINNED_GLOBS=(
    "/etc/systemd/system/swift-vapor*.service"
    "/etc/systemd/system/swift-vapor*.timer"
    "/etc/systemd/system/swift-vapor*.service.d/*.conf"
    "/etc/nginx/sites-available/swift.micutu.com"
    "/etc/nginx/sites-available/swift-onion.conf"
    "/etc/nginx/snippets/swift-csp.conf"
    "/etc/swift-vapor/*.env"
    "/usr/local/libexec/swift-vapor/*"
)

usage() { echo "usage: $0 --accept | --verify | --print" >&2; }

MODE=""
while (( $# > 0 )); do
    case "$1" in
        --accept) MODE=accept; shift ;;
        --verify) MODE=verify; shift ;;
        --print)  MODE=print;  shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done
[[ -n "$MODE" ]] || { usage; exit 2; }

if [[ "$MANIFEST" != /* ]]; then
    echo "config-manifest: manifest path must be absolute." >&2
    exit 2
fi

collect() {
    shopt -s nullglob
    local path
    for glob in "${PINNED_GLOBS[@]}"; do
        for path in $glob; do
            # Editor and rollback leftovers are not configuration.
            case "$path" in
                *.bak-*|*.dpkg-*|*.ucf-*|*~) continue ;;
            esac
            [[ -f "$path" ]] || continue
            printf '%s\t%s\t%s\t%s\n' \
                "$path" \
                "$(sha256sum "$path" | cut -d' ' -f1)" \
                "$(stat -c '%a' "$path")" \
                "$(stat -c '%U:%G' "$path")"
        done
    done | sort
}

release_sha="unknown"
if [[ -L "$CURRENT_LINK" ]]; then
    release_sha="$(basename "$(readlink -f "$CURRENT_LINK")")"
fi

build_json() {
    RELEASE_SHA="$release_sha" python3 -c '
import json, os, sys
entries = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    path, digest, mode, owner = line.split("\t")
    entries.append({"path": path, "sha256": digest, "mode": mode, "owner": owner})
json.dump({
    "version": 1,
    "release": os.environ["RELEASE_SHA"],
    "entries": entries,
}, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
'
}

case "$MODE" in
    print)
        collect | build_json
        ;;

    accept)
        install -d -o root -g root -m 0750 "$(dirname "$MANIFEST")"
        tmp="$(mktemp)"
        trap 'rm -f "$tmp"' EXIT
        collect | build_json > "$tmp"
        install -o root -g root -m 0640 "$tmp" "$MANIFEST"
        count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["entries"]))' "$MANIFEST")"
        echo "config-manifest: accepted $count file(s) as the baseline for release $release_sha."
        ;;

    verify)
        if [[ ! -f "$MANIFEST" ]]; then
            echo "config-manifest: no baseline at $MANIFEST — run --accept once to record one." >&2
            exit 1
        fi
        live="$(mktemp)"
        trap 'rm -f "$live"' EXIT
        collect | build_json > "$live"
        MANIFEST_PATH="$MANIFEST" LIVE_PATH="$live" python3 -c '
import json, os, sys

def load(path):
    with open(path) as handle:
        data = json.load(handle)
    return {entry["path"]: entry for entry in data["entries"]}, data.get("release", "unknown")

accepted, accepted_release = load(os.environ["MANIFEST_PATH"])
live, live_release = load(os.environ["LIVE_PATH"])

problems = []
for path in sorted(set(accepted) | set(live)):
    want, have = accepted.get(path), live.get(path)
    if want is None:
        problems.append(f"added:    {path}")
    elif have is None:
        problems.append(f"removed:  {path}")
    elif want["sha256"] != have["sha256"]:
        problems.append(f"modified: {path}")
    elif (want["mode"], want["owner"]) != (have["mode"], have["owner"]):
        before = want["mode"] + " " + want["owner"]
        after = have["mode"] + " " + have["owner"]
        problems.append("permissions: " + path + " (" + before + " -> " + after + ")")

if not problems:
    print(f"config-manifest: {len(live)} pinned file(s) match the baseline (release {accepted_release}).")
    sys.exit(0)

print(f"config-manifest: {len(problems)} configuration drift(s) against the baseline:", file=sys.stderr)
for problem in problems:
    print(f"  - {problem}", file=sys.stderr)
print("Review the change, then either revert it or re-run --accept to adopt it.", file=sys.stderr)
sys.exit(1)
'
        ;;
esac
