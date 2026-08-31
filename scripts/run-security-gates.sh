#!/usr/bin/env bash
set -euo pipefail

readonly GITLEAKS_IMAGE="ghcr.io/gitleaks/gitleaks@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854"
readonly SEMGREP_IMAGE="semgrep/semgrep@sha256:65dcd4408adda7c183a6b4550cb1e9b19f7f627a6fbb7e0559bd466bedc44d7b"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REPOSITORY_ROOT

usage() {
    printf 'Usage: %s {self-test|scan|working-tree}\n' "$0" >&2
}

# Env-shaped files in the working tree that carry a real secret value.
#
# Gitleaks scans Git history and semgrep scans source, so between them nothing
# looks at an *untracked* file sitting next to them. That is exactly where the
# problem turned up: a `.env.bak-mailcow-<timestamp>` copy of this project's own
# environment, holding the live ENCRYPTION_KEY, DATABASE_PASSWORD, ADMIN_PASSWORD
# and three API keys, gitignored and therefore invisible to every gate here.
#
# One `.env` is how the project is developed and is deliberately allowed. What
# is not allowed is the second copy: an editor backup, a pre-migration snapshot,
# a `.env.save` — names nobody predicts, that nobody prunes, and that hold the
# key to every encrypted field in the database. `*.example` files are templates
# and are allowed to carry placeholder values.
#
# Prints paths only; values never leave the file.
stray_secret_files() {
    local root="$1" path relative
    local secret_assignment='^[[:space:]]*([A-Z0-9_]*(PASSWORD|PASS|TOKEN|SECRET|PRIVATE_KEY|API_KEY)|ENCRYPTION_KEY|AUDIT_SIGNING_KEY|AUDIT_COMMITMENT_KEY)=[^[:space:]]{8,}'
    while IFS= read -r path; do
        relative="${path#"${root}"/}"
        [[ "$relative" == ".env" ]] && continue
        [[ "$path" == *.example ]] && continue
        if grep -Eq "$secret_assignment" "$path" 2>/dev/null; then
            printf '%s\n' "$relative"
        fi
    done < <(
        find "$root" \
            \( -name .git -o -name .build -o -name node_modules \) -prune -o \
            -type f \( -name '.env' -o -name '.env.*' -o -name '*.env' -o -name '*.env.*' \) \
            -print
    )
}

scan_working_tree() {
    local findings
    findings="$(stray_secret_files "$REPOSITORY_ROOT")"
    if [[ -n "$findings" ]]; then
        printf 'Plaintext secrets in files outside the single allowed .env:\n' >&2
        printf '  %s\n' "$findings" >&2
        printf 'Move the value into a systemd credential, or shred the file.\n' >&2
        return 1
    fi
    printf 'No stray plaintext secret files in the working tree.\n'
}

run_semgrep() {
    local target="$1"
    shift
    docker run --rm --network none \
        --volume "${REPOSITORY_ROOT}:/src:ro" \
        --volume "${target}:/target:ro" \
        "$SEMGREP_IMAGE" semgrep scan \
        --config /src/.semgrep.yml \
        --error \
        --strict \
        --metrics=off \
        --disable-version-check \
        --jobs 2 \
        --timeout 15 \
        "$@" \
        /target
}

self_test() {
    local fixture_root positive_dir negative_dir
    fixture_root="$(mktemp -d)"
    trap 'rm -rf -- "$fixture_root"' RETURN
    positive_dir="${fixture_root}/positive"
    negative_dir="${fixture_root}/negative"
    mkdir -p -- "$positive_dir" "$negative_dir"

    # Assemble a high-entropy fake API value only in the disposable fixture.
    # Both the key label and value are split below, so the control itself never
    # creates a secret-shaped value in Git history.
    printf '%s%s = "%s%s%s%s%s%s%s%s"\n' \
        'api_' 'key' 'N7vL' '2qR8' 'xK4m' 'P9sT' \
        '6wY3' 'cF5h' 'J1zB' '0dGQ' \
        > "${positive_dir}/fake-secret.py"
    printf '%s\n' 'import subprocess' \
        'subprocess.run("id", shell=True, check=True)' \
        > "${positive_dir}/unsafe-subprocess.py"
    printf '%s\n' 'import subprocess' \
        'subprocess.run(["id"], check=True)' \
        > "${negative_dir}/safe-subprocess.py"

    if docker run --rm --network none \
        --volume "${positive_dir}:/fixture:ro" \
        "$GITLEAKS_IMAGE" dir --no-banner --no-color --redact=100 \
        --log-level error /fixture >/dev/null 2>&1; then
        printf 'gitleaks positive control was not detected\n' >&2
        return 1
    fi

    docker run --rm --network none \
        --volume "${negative_dir}:/fixture:ro" \
        "$GITLEAKS_IMAGE" dir --no-banner --no-color --redact=100 \
        --log-level error /fixture >/dev/null

    if run_semgrep "$positive_dir" >/dev/null 2>&1; then
        printf 'semgrep positive control was not detected\n' >&2
        return 1
    fi
    run_semgrep "$negative_dir" >/dev/null 2>&1

    # The working-tree check needs its own controls: it is the only gate here
    # that would have caught the file that prompted it.
    printf '%s\n' 'ENCRYPTION_KEY=0123456789abcdef0123456789abcdef' \
        > "${positive_dir}/.env.bak-fixture"
    printf '%s\n' 'ENCRYPTION_KEY=replace-me-with-64-hex-characters' \
        > "${negative_dir}/.env.example"
    printf '%s\n' 'ENCRYPTION_KEY=0123456789abcdef0123456789abcdef' \
        > "${negative_dir}/.env"
    printf '%s\n' 'DATABASE_PASSWORD_FILE=/run/credentials/database-password' \
        > "${negative_dir}/paths.env"

    [[ "$(stray_secret_files "$positive_dir")" == ".env.bak-fixture" ]] || {
        printf 'working-tree positive control was not detected\n' >&2
        return 1
    }
    [[ -z "$(stray_secret_files "$negative_dir")" ]] || {
        printf 'working-tree negative control was flagged\n' >&2
        return 1
    }

    printf 'Security scanner positive and negative controls passed.\n'
}

scan_repository() {
    docker run --rm --network none \
        --volume "${REPOSITORY_ROOT}:/repo:ro" \
        --workdir /repo \
        "$GITLEAKS_IMAGE" git --no-banner --no-color --redact=100 \
        --gitleaks-ignore-path /repo/.gitleaksignore /repo

    run_semgrep "$REPOSITORY_ROOT" \
        --exclude .git \
        --exclude .build \
        --exclude frontend/node_modules \
        --exclude frontend/d3.min.js \
        --exclude frontend/leaflet.js \
        --exclude frontend/docs/swagger-ui-bundle.js

    scan_working_tree
}

case "${1:-}" in
    self-test)
        self_test
        ;;
    scan)
        scan_repository
        ;;
    working-tree)
        scan_working_tree
        ;;
    *)
        usage
        exit 64
        ;;
esac
