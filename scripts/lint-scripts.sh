#!/usr/bin/env bash

# Syntax and lint gate for every script in the repository.
#
# The list of scripts is *derived*, never hand-kept. The previous gate was a
# bash array pasted into .github/workflows/ci.yml, and it had already drifted:
# three root-run scripts added later — one of them handling the alert relay's
# API key — were never linted, and nothing anywhere reported the gap. A list
# that has to be edited in a second place to stay correct will eventually be
# wrong, so this discovers its own inputs instead.
#
#   check      lint everything discovered (the gate)
#   list       print what would be linted, as "kind<TAB>path"
#   self-test  positive controls: prove the gate actually rejects bad scripts,
#              and that discovery is by content rather than by file extension
#
# Discovery is by shebang over Git's view of the tree (tracked files plus
# untracked-but-not-ignored ones, so a script added locally is covered before
# it is ever committed), which is what makes extensionless scripts such as
# ops/libexec/update-swift-csp show up on their own.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly REPOSITORY_ROOT

usage() {
    printf 'Usage: %s {check|list|self-test}\n' "$0" >&2
}

# Emits "kind<TAB>path" for every script found, kind ∈ {bash, sh, python}.
# A .sh file with no shebang still counts as sh: an unreadable first line is
# not a reason to skip a file this gate exists to cover.
discover() {
    local file first
    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        first="$(head -n 1 -- "$file" 2>/dev/null || true)"
        case "$first" in
            '#!'*bash*)             printf 'bash\t%s\n'   "$file" ;;
            '#!'*python*)           printf 'python\t%s\n' "$file" ;;
            '#!'*sh*)               printf 'sh\t%s\n'     "$file" ;;
            *)
                case "$file" in
                    *.sh) printf 'sh\t%s\n' "$file" ;;
                    *.py) printf 'python\t%s\n' "$file" ;;
                esac
                ;;
        esac
    done < <(git -C "$REPOSITORY_ROOT" ls-files --cached --others --exclude-standard)
}

check() {
    local -a bash_scripts=() sh_scripts=() python_scripts=()
    local kind file
    while IFS=$'\t' read -r kind file; do
        case "$kind" in
            bash)   bash_scripts+=("$file") ;;
            sh)     sh_scripts+=("$file") ;;
            python) python_scripts+=("$file") ;;
        esac
    done < <(discover)

    if (( ${#bash_scripts[@]} + ${#sh_scripts[@]} + ${#python_scripts[@]} == 0 )); then
        printf 'lint-scripts: discovered nothing, which cannot be right.\n' >&2
        return 1
    fi

    local status=0
    if (( ${#bash_scripts[@]} > 0 )); then
        bash -n -- "${bash_scripts[@]}" || status=1
    fi
    if (( ${#sh_scripts[@]} > 0 )); then
        for file in "${sh_scripts[@]}"; do
            sh -n -- "$file" || status=1
        done
    fi
    if (( ${#bash_scripts[@]} + ${#sh_scripts[@]} > 0 )); then
        shellcheck -- "${bash_scripts[@]}" "${sh_scripts[@]}" || status=1
    fi
    if (( ${#python_scripts[@]} > 0 )); then
        # ast.parse rather than py_compile: same syntax check, no __pycache__
        # written back into a tree this gate is only supposed to read.
        python3 - "${python_scripts[@]}" <<'PY' || status=1
import ast, sys
failed = False
for path in sys.argv[1:]:
    try:
        with open(path, "rb") as handle:
            ast.parse(handle.read(), filename=path)
    except SyntaxError as error:
        print(f"{path}:{error.lineno}: {error.msg}", file=sys.stderr)
        failed = True
sys.exit(1 if failed else 0)
PY
    fi

    if (( status == 0 )); then
        printf 'lint-scripts: %d bash, %d sh, %d python scripts pass.\n' \
            "${#bash_scripts[@]}" "${#sh_scripts[@]}" "${#python_scripts[@]}"
    fi
    return "$status"
}

# The gate is only worth anything if it fails on a bad script, so prove it —
# and prove it against files the gate has to *discover*, not files handed to it.
self_test() {
    local fixture
    fixture="$(mktemp -d -- "${REPOSITORY_ROOT}/.lint-selftest.XXXXXX")"
    trap 'rm -rf -- "$fixture"' RETURN
    local name="${fixture##*/}"

    assert_rejected() {
        local label="$1"
        if check >/dev/null 2>&1; then
            printf 'lint-scripts self-test: %s was NOT rejected\n' "$label" >&2
            return 1
        fi
    }

    # A clean script must pass — otherwise every assertion below could be
    # succeeding for the wrong reason.
    printf '#!/usr/bin/env bash\nset -euo pipefail\necho ok\n' > "${fixture}/clean.sh"
    if ! check >/dev/null 2>&1; then
        printf 'lint-scripts self-test: a clean fixture was rejected\n' >&2
        return 1
    fi
    rm -f -- "${fixture}/clean.sh"

    # 1. Syntax error, caught by bash -n.
    printf '#!/usr/bin/env bash\nif true; then\n' > "${fixture}/broken.sh"
    assert_rejected 'a bash syntax error' || return 1
    rm -f -- "${fixture}/broken.sh"

    # 2. Syntactically valid, but a shellcheck finding — proves shellcheck runs
    #    and is not merely shadowed by the parse check.
    # shellcheck disable=SC2016  # the literal $1 is the point of the fixture
    printf '#!/usr/bin/env bash\nrm -rf $1\n' > "${fixture}/unquoted.sh"
    assert_rejected 'an unquoted expansion' || return 1
    rm -f -- "${fixture}/unquoted.sh"

    # 3. No extension at all: discovery must be reading shebangs.
    printf '#!/usr/bin/env bash\nfor x in; do\n' > "${fixture}/extensionless"
    chmod +x -- "${fixture}/extensionless"
    assert_rejected 'an extensionless bash script' || return 1
    rm -f -- "${fixture}/extensionless"

    # 4. Python is covered by the same discovery.
    printf '#!/usr/bin/env python3\ndef broken(:\n' > "${fixture}/broken.py"
    assert_rejected 'a python syntax error' || return 1
    rm -f -- "${fixture}/broken.py"

    # 5. And the fixtures were genuinely being discovered, not silently skipped:
    #    a passing gate above with an undiscovered fixture would look identical.
    printf '#!/usr/bin/env bash\ntrue\n' > "${fixture}/discovered.sh"
    # Not `discover | grep -q`: under `set -o pipefail`, grep -q closing the
    # pipe early makes the whole pipeline report discover's SIGPIPE instead.
    local listing
    listing="$(discover)"
    if ! grep -q "${name}/discovered.sh" <<<"$listing"; then
        printf 'lint-scripts self-test: discovery missed a new script\n' >&2
        return 1
    fi

    printf 'lint-scripts: self-test passed (5 positive controls, 1 negative).\n'
}

case "${1:-}" in
    check)     check ;;
    list)      discover ;;
    self-test) self_test ;;
    *)         usage; exit 64 ;;
esac
