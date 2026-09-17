#!/usr/bin/env bash
set -euo pipefail

# mcr.microsoft.com/playwright:v1.63.0-noble. The digest pins the bytes; the tag
# is written here so the next bump knows what it is replacing. It must match
# the locked @playwright/test — the preflight below refuses a mismatch by name.
readonly PLAYWRIGHT_IMAGE="mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27"
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

docker_flags=(
    --rm --init --network none --shm-size 1g
    --user "$(id -u):$(id -g)"
    --cap-drop ALL
    --pids-limit 512
    --security-opt no-new-privileges
    --read-only
    --tmpfs "/tmp:rw,exec,nosuid,nodev,mode=1777,size=768m"
    --tmpfs "/root:rw,nosuid,nodev,mode=1777,size=64m"
    --env CI=1
    --env PLAYWRIGHT_OUTPUT_DIR=/artifacts/test-results
    --env PLAYWRIGHT_REPORT_DIR=/artifacts/html-report
    --volume "${REPOSITORY_ROOT}:/repo:ro"
    --volume "${OUTPUT_DIRECTORY}:/artifacts"
    --workdir /repo/frontend
)

# Same sandbox, one short run first: a package/image mismatch fails here with a
# sentence naming both versions, instead of as every test's launch error.
docker run "${docker_flags[@]}" "$PLAYWRIGHT_IMAGE" \
    node /repo/scripts/playwright-image-preflight.mjs /repo/frontend /ms-playwright

docker run "${docker_flags[@]}" "$PLAYWRIGHT_IMAGE" \
    node_modules/.bin/playwright test "$@"
