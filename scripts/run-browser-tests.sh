#!/usr/bin/env bash
set -euo pipefail

readonly PLAYWRIGHT_IMAGE="mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REPOSITORY_ROOT

if [ "$#" -lt 1 ]; then
    printf 'Usage: %s OUTPUT_DIRECTORY [PLAYWRIGHT_ARGUMENT ...]\n' "$0" >&2
    exit 64
fi

mkdir -p -- "$1"
OUTPUT_DIRECTORY="$(cd -- "$1" && pwd -P)"
readonly OUTPUT_DIRECTORY
shift

docker run --rm --init --network none --shm-size 1g \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --pids-limit 512 \
    --security-opt no-new-privileges \
    --read-only \
    --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777,size=768m \
    --tmpfs /root:rw,nosuid,nodev,mode=1777,size=64m \
    --env CI=1 \
    --env PLAYWRIGHT_OUTPUT_DIR=/artifacts/test-results \
    --env PLAYWRIGHT_REPORT_DIR=/artifacts/html-report \
    --volume "${REPOSITORY_ROOT}:/repo:ro" \
    --volume "${OUTPUT_DIRECTORY}:/artifacts" \
    --workdir /repo/frontend \
    "$PLAYWRIGHT_IMAGE" \
    node_modules/.bin/playwright test "$@"
