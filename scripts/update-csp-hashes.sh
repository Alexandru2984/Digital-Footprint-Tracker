#!/usr/bin/env bash

# Compute the exact CSP hashes for one frontend, or the union for a zero-downtime
# old->new transition, then hand only validated hash tokens to a root-owned
# installer. This script itself never writes nginx configuration.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRINT_ONLY=0
if [[ "${1:-}" == "--print" ]]; then
    PRINT_ONLY=1
    shift
fi

if (( $# > 2 )); then
    echo "usage: $0 [--print] [FRONTEND [TRANSITION_FRONTEND]]" >&2
    exit 2
fi

frontends=("${1:-/srv/swift-vapor/current/frontend}")
[[ $# -lt 2 ]] || frontends+=("$2")
for frontend in "${frontends[@]}"; do
    [[ "$frontend" == /* && -d "$frontend" ]] || {
        echo "[csp] frontend is missing or not absolute: $frontend" >&2
        exit 1
    }
done

mapfile -t hashes < <(node "$SCRIPT_DIR/csp-hashes.mjs" "${frontends[@]}")
(( ${#hashes[@]} > 0 )) || { echo "[csp] no hashes generated" >&2; exit 1; }

if (( PRINT_ONLY )); then
    printf '%s\n' "${hashes[@]}"
    exit 0
fi

HELPER=/usr/local/sbin/update-swift-csp
[[ -x "$HELPER" ]] || { echo "[csp] root-owned installer missing: $HELPER" >&2; exit 1; }
echo "[csp] installing ${#hashes[@]} validated script hashes"
sudo -n "$HELPER" "${hashes[@]}"
