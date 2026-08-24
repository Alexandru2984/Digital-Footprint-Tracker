#!/usr/bin/env bash
set -euo pipefail

readonly SYFT_IMAGE="anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REPOSITORY_ROOT

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s OUTPUT_DIRECTORY\n' "$0" >&2
    exit 64
fi

umask 077
mkdir -p -- "$1"
OUTPUT_DIRECTORY="$(cd -- "$1" && pwd -P)"
readonly OUTPUT_DIRECTORY
SOURCE_VERSION="$(git -C "$REPOSITORY_ROOT" rev-parse --verify HEAD)"
readonly SOURCE_VERSION
readonly SPDX_PATH="${OUTPUT_DIRECTORY}/digital-footprint-tracker.spdx.json"
readonly CYCLONEDX_PATH="${OUTPUT_DIRECTORY}/digital-footprint-tracker.cyclonedx.json"

docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    --env SYFT_CHECK_FOR_APP_UPDATE=false \
    --env XDG_CACHE_HOME=/tmp/syft-cache \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=64m \
    --volume "${REPOSITORY_ROOT}:/src:ro" \
    --volume "${OUTPUT_DIRECTORY}:/out" \
    --workdir /src \
    "$SYFT_IMAGE" scan dir:/src \
    --source-name digital-footprint-tracker \
    --source-version "$SOURCE_VERSION" \
    --exclude './.git/**' \
    --exclude './.build/**' \
    --exclude './frontend/node_modules/**' \
    --output spdx-json=/out/digital-footprint-tracker.spdx.json \
    --output cyclonedx-json=/out/digital-footprint-tracker.cyclonedx.json \
    >/dev/null

# Reject syntactically valid but materially incomplete output. The repository
# intentionally has all three ecosystems and the release SBOM must retain them.
jq -e '
    .spdxVersion == "SPDX-2.3" and
    (.packages | length) > 0 and
    any(.packages[].externalRefs[]?.referenceLocator; startswith("pkg:swift/")) and
    any(.packages[].externalRefs[]?.referenceLocator; startswith("pkg:npm/")) and
    any(.packages[].externalRefs[]?.referenceLocator; startswith("pkg:pypi/"))
' "$SPDX_PATH" >/dev/null

jq -e '
    .bomFormat == "CycloneDX" and
    (.components | length) > 0 and
    any(.components[]?.purl; startswith("pkg:swift/")) and
    any(.components[]?.purl; startswith("pkg:npm/")) and
    any(.components[]?.purl; startswith("pkg:pypi/"))
' "$CYCLONEDX_PATH" >/dev/null

printf 'Validated SPDX and CycloneDX SBOMs in %s\n' "$OUTPUT_DIRECTORY"
