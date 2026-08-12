#!/usr/bin/env bash

# Shared, side-effect-light validation helpers for immutable release bundles.
# Callers must enable their preferred shell strictness before sourcing this file.

release_manifest_value() {
    local release="$1" key="$2"
    awk -F= -v wanted="$key" '$1 == wanted { print substr($0, length($1) + 2); exit }' \
        "$release/RELEASE"
}

verify_release() {
    local release="$1" release_root="$2"
    local resolved root_resolved name expected_commit expected_run expected_frontend expected_files

    [[ "$release" == /* && "$release_root" == /* ]] || return 1
    [[ -d "$release" && ! -L "$release" ]] || return 1
    resolved="$(realpath -e -- "$release")" || return 1
    root_resolved="$(realpath -e -- "$release_root")" || return 1
    [[ "$(dirname -- "$resolved")" == "$root_resolved" ]] || return 1
    name="$(basename -- "$resolved")"
    [[ "$name" =~ ^[0-9a-f]{40}$ ]] || return 1

    [[ -f "$resolved/Run" && ! -L "$resolved/Run" && -x "$resolved/Run" ]] || return 1
    [[ -f "$resolved/frontend/index.html" && ! -L "$resolved/frontend/index.html" ]] || return 1
    [[ -f "$resolved/scripts/generate_report.py" && ! -L "$resolved/scripts/generate_report.py" ]] || return 1
    [[ -f "$resolved/DigitalFootprintTracker_App.resources/sherlock_data.json" ]] || return 1
    [[ -f "$resolved/RELEASE" && ! -L "$resolved/RELEASE" ]] || return 1
    [[ -f "$resolved/SHA256SUMS" && ! -L "$resolved/SHA256SUMS" ]] || return 1
    [[ -z "$(find "$resolved" -type l -print -quit)" ]] || return 1
    [[ -z "$(find "$resolved" -perm /022 -print -quit)" ]] || return 1

    expected_commit="$(release_manifest_value "$resolved" commit)"
    expected_run="$(release_manifest_value "$resolved" run_sha256)"
    expected_frontend="$(release_manifest_value "$resolved" frontend_index_sha256)"
    expected_files="$(release_manifest_value "$resolved" files_manifest_sha256)"
    [[ "$expected_commit" == "$name" ]] || return 1
    [[ "$expected_run" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$expected_frontend" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$expected_files" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$(sha256sum "$resolved/Run" | awk '{print $1}')" == "$expected_run" ]] || return 1
    [[ "$(sha256sum "$resolved/frontend/index.html" | awk '{print $1}')" == "$expected_frontend" ]] || return 1
    [[ "$(sha256sum "$resolved/SHA256SUMS" | awk '{print $1}')" == "$expected_files" ]] || return 1
    (cd "$resolved" && sha256sum --check --strict --status SHA256SUMS) || return 1
    [[ "$(( $(find "$resolved" -type f | wc -l) - 2 ))" -eq "$(wc -l < "$resolved/SHA256SUMS")" ]] || return 1
}

switch_release_link() {
    local target="$1" link="$2" release_root="$3"
    local temporary

    verify_release "$target" "$release_root" || {
        echo "release: refusing to link an invalid bundle: $target" >&2
        return 1
    }
    [[ "$link" == /* && "$(dirname -- "$link")" == "$(dirname -- "$release_root")" ]] || {
        echo "release: refusing an unexpected release-link path: $link" >&2
        return 1
    }
    [[ ! -e "$link" || -L "$link" ]] || {
        echo "release: destination exists and is not a symlink: $link" >&2
        return 1
    }

    temporary="${link}.new.$$"
    [[ ! -e "$temporary" && ! -L "$temporary" ]] || {
        echo "release: temporary link already exists: $temporary" >&2
        return 1
    }
    ln -s -- "$target" "$temporary"
    if ! mv -Tf -- "$temporary" "$link"; then
        rm -f -- "$temporary"
        return 1
    fi
}
