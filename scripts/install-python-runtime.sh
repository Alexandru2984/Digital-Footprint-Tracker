#!/usr/bin/env bash

# Installs the Python runtime the application shells out to: fpdf2 for PDF
# reports and holehe for email account discovery.
#
# The container image builds this into /opt/python-runtime. The systemd
# deployment never had it, so in production both features failed without a
# word to the user: reports could not import fpdf, and holehe was "not found"
# on every scan that wanted it.
#
# Releases are keyed by the hash of the locked requirements, so a dependency
# change builds a new one beside the old and `current` switches atomically. A
# virtualenv is not relocatable — its scripts carry absolute shebangs — so each
# release is built in its final directory, never staged and moved.

set -euo pipefail
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin

[[ $EUID -eq 0 ]] || { echo "install-python-runtime: must run as root" >&2; exit 1; }

REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly REQUIREMENTS="${REPOSITORY_ROOT}/requirements-runtime.txt"
readonly PYTHON_BIN="${SWIFT_VAPOR_PYTHON_BIN:-/usr/bin/python3}"
readonly INSTALL_ROOT="/opt/swift-vapor-python"

[[ -r "$REQUIREMENTS" ]] || { echo "install-python-runtime: missing $REQUIREMENTS" >&2; exit 1; }
[[ -x "$PYTHON_BIN" ]] || { echo "install-python-runtime: no interpreter at $PYTHON_BIN" >&2; exit 1; }

digest="$(sha256sum "$REQUIREMENTS" | cut -c1-16)"
release="${INSTALL_ROOT}/releases/${digest}"
install -d -m 0755 -o root -g root "$INSTALL_ROOT" "${INSTALL_ROOT}/releases"

if [[ ! -x "${release}/bin/python3" ]]; then
    echo "install-python-runtime: building ${release}"
    rm -rf -- "$release"
    trap 'rm -rf -- "$release"' ERR
    "$PYTHON_BIN" -m venv "$release"
    # Hash-locked, binary wheels only — nothing native compiles on this host.
    # holehe is the one exception: this version publishes no wheel, and it is
    # pure Python, so building it from source compiles nothing either.
    "${release}/bin/python" -m pip install \
        --no-cache-dir --disable-pip-version-check --quiet \
        --require-hashes --only-binary=:all: --no-binary=holehe \
        --requirement "$REQUIREMENTS"
    trap - ERR
fi

# Prove the release works before anything points at it.
"${release}/bin/python3" -c 'import fpdf' \
    || { echo "install-python-runtime: fpdf2 does not import" >&2; exit 1; }
[[ -x "${release}/bin/holehe" ]] \
    || { echo "install-python-runtime: holehe is missing" >&2; exit 1; }

ln -sfn "$release" "${INSTALL_ROOT}/.current.new"
mv -T "${INSTALL_ROOT}/.current.new" "${INSTALL_ROOT}/current"

echo "install-python-runtime: ${INSTALL_ROOT}/current -> ${release}"
echo "  REPORT_PYTHON_PATH=${INSTALL_ROOT}/current/bin/python3"
echo "  HOLEHE_PATH=${INSTALL_ROOT}/current/bin/holehe"
