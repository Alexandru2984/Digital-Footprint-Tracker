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
#   --accept        record the current state as the accepted baseline
#   --verify        compare the live state against the baseline (exit 1 on drift)
#   --print         write the manifest that would be accepted to stdout, change
#                   nothing
#   --accept-path P re-pin exactly one already-pinned file, leaving every other
#                   entry untouched. For the sanctioned writer of a file to
#                   adopt its own change: a deploy rewrites the CSP snippet
#                   through update-swift-csp every time, which would otherwise
#                   put this gate into permanent, expected failure — and a gate
#                   that is expected to fail is a gate nobody reads. P must
#                   already be covered by PINNED_GLOBS, so this can never be
#                   used to admit a file the baseline does not describe.
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
# Overridable only so the contract test can point at a fixture tree; production
# never sets it. Anything able to set this variable on a root process already
# controls the process.
if [[ -n "${CONFIG_MANIFEST_GLOBS:-}" ]]; then
    read -r -a PINNED_GLOBS <<< "$CONFIG_MANIFEST_GLOBS"
else
PINNED_GLOBS=(
    "/etc/systemd/system/swift-vapor*.service"
    "/etc/systemd/system/swift-vapor*.timer"
    "/etc/systemd/system/swift-vapor*.service.d/*.conf"
    "/etc/nginx/sites-available/swift.micutu.com"
    "/etc/nginx/sites-available/swift-onion.conf"
    "/etc/nginx/snippets/swift-*.conf"
    "/etc/swift-vapor/*.env"
    "/usr/local/libexec/swift-vapor/*"
    # The narrow privilege boundary the deploy account can invoke as root.
    # It lives outside libexec, so it was the one root-owned helper in this
    # design that nothing watched.
    "/usr/local/sbin/update-swift-csp"
)
fi

usage() { echo "usage: $0 --accept | --verify | --print | --accept-path PATH" >&2; }

MODE=""
ACCEPT_PATH=""
while (( $# > 0 )); do
    case "$1" in
        --accept) MODE=accept; shift ;;
        --accept-path)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            MODE=accept-path; ACCEPT_PATH="$2"; shift 2 ;;
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

# root sets root ownership; anyone else cannot, and the production manifest
# lives in a 0750 root-owned directory they cannot write to anyway. Keeping this
# conditional is what lets the contract test exercise the real script.
install_manifest_directory() {
    if [[ $EUID -eq 0 ]]; then
        install -d -o root -g root -m 0750 "$(dirname "$MANIFEST")"
    else
        install -d -m 0700 "$(dirname "$MANIFEST")"
    fi
}

install_manifest() {
    if [[ $EUID -eq 0 ]]; then
        install -o root -g root -m 0640 "$1" "$MANIFEST"
    else
        install -m 0600 "$1" "$MANIFEST"
    fi
}

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
            # The record is tab-separated; a path carrying a tab or newline
            # would parse into a different entry than the file it came from.
            # Refuse loudly rather than write a manifest that lies.
            if [[ "$path" == *$'\t'* || "$path" == *$'\n'* ]]; then
                echo "config-manifest: refusing a path containing a tab or newline." >&2
                exit 1
            fi
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
        install_manifest_directory
        tmp="$(mktemp)"
        trap 'rm -f "$tmp"' EXIT
        collect | build_json > "$tmp"
        install_manifest "$tmp"
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

# The release SHA is metadata, not a pinned entry: a deploy legitimately moves
# the symlink without touching any host configuration, so a mismatch here is
# worth saying out loud but is never drift.
release_note = ""
if accepted_release != live_release:
    release_note = (
        f" Baseline was accepted against release {accepted_release}; "
        f"the deployed release is now {live_release}."
    )

if not problems:
    print(f"config-manifest: {len(live)} pinned file(s) match the baseline.{release_note}")
    sys.exit(0)

print(f"config-manifest: {len(problems)} configuration drift(s) against the baseline.{release_note}", file=sys.stderr)
for problem in problems:
    print(f"  - {problem}", file=sys.stderr)
print("Review the change, then either revert it or re-run --accept to adopt it.", file=sys.stderr)
sys.exit(1)
'
        ;;
    accept-path)
        if [[ "$ACCEPT_PATH" != /* ]]; then
            echo "config-manifest: --accept-path needs an absolute path." >&2
            exit 2
        fi
        if [[ ! -f "$MANIFEST" ]]; then
            echo "config-manifest: no baseline at $MANIFEST — run --accept once to record one." >&2
            exit 1
        fi
        live="$(mktemp)"
        tmp="$(mktemp)"
        trap 'rm -f "$live" "$tmp"' EXIT
        collect > "$live"
        # Exit 3 means "the entry is already correct" — separated from 0 so the
        # caller never installs a manifest that was not rewritten.
        status=0
        MANIFEST_PATH="$MANIFEST" LIVE_PATH="$live" TARGET="$ACCEPT_PATH" python3 -c '
import json, os, sys

target = os.environ["TARGET"]

live = {}
with open(os.environ["LIVE_PATH"]) as handle:
    for line in handle:
        line = line.rstrip("\n")
        if not line:
            continue
        path, digest, mode, owner = line.split("\t")
        live[path] = {"path": path, "sha256": digest, "mode": mode, "owner": owner}

# Two independent gates. The first is what keeps this from being a way to admit
# anything: the path has to be a file the globs already cover. The second is
# stricter still — a file that is genuinely new to the baseline is a human
# decision, so it goes through --accept, not through the writer that made it.
if target not in live:
    sys.exit(f"config-manifest: {target} is not a pinned, existing file — refusing to re-pin it.")

with open(os.environ["MANIFEST_PATH"]) as handle:
    data = json.load(handle)

entries = data["entries"]
for index, entry in enumerate(entries):
    if entry["path"] == target:
        break
else:
    sys.exit(f"config-manifest: {target} is not in the baseline — run --accept once to record it.")

if entries[index] == live[target]:
    sys.exit(3)

entries[index] = live[target]
data["entries"] = sorted(entries, key=lambda entry: entry["path"])
json.dump(data, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
' > "$tmp" || status=$?

        case "$status" in
            0)
                [[ -s "$tmp" ]] || { echo "config-manifest: refusing to install an empty manifest." >&2; exit 1; }
                install_manifest "$tmp"
                echo "config-manifest: re-pinned $ACCEPT_PATH; every other entry is unchanged."
                ;;
            3)
                echo "config-manifest: $ACCEPT_PATH already matches the baseline; nothing to re-pin."
                ;;
            *)
                exit "$status"
                ;;
        esac
        ;;

esac
