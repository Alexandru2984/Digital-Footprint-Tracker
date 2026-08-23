#!/usr/bin/env bash
set -euo pipefail

# Stages the reviewed VoidAccess release and the isolated adapter. It installs
# no optional LLM/vector/browser extras, does not enable the feature flag, and
# does not start or restart either service.

umask 077

readonly VOIDACCESS_VERSION="2.0.3"
readonly VOIDACCESS_COMMIT="be276d1219a0af9306d5390b6a07bb23f67f7746"
readonly VOIDACCESS_SOURCE_SHA256="b6ef73c8b0d12ee603fccc51af274478bfd7505f44d00fecb8ea64b3a937551f"
readonly VOIDACCESS_SOURCE_URL="https://codeload.github.com/KatrielMoses/voidaccess/tar.gz/${VOIDACCESS_COMMIT}"
readonly SPACY_MODEL_VERSION="3.8.0"
readonly SPACY_MODEL_SHA256="1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85"
readonly SPACY_MODEL_URL="https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-${SPACY_MODEL_VERSION}/en_core_web_sm-${SPACY_MODEL_VERSION}-py3-none-any.whl"
readonly PYTHON_BIN="${VOIDACCESS_PYTHON_BIN:-/usr/bin/python3.13}"
readonly INSTALL_ROOT="/opt/voidaccess"
readonly RELEASES_ROOT="${INSTALL_ROOT}/releases"
readonly RELEASE_DIR="${RELEASES_ROOT}/${VOIDACCESS_COMMIT}"
readonly ADAPTER_ROOT="/opt/swift-voidaccess"

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this installer as root (for example: sudo scripts/install-voidaccess.sh)." >&2
    exit 1
fi

REPOSITORY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly REQUIREMENTS="${REPOSITORY_ROOT}/worker/requirements-voidaccess-v2.0.3.txt"
readonly ADAPTER_SOURCE="${REPOSITORY_ROOT}/worker/voidaccess_worker.py"
readonly ENTRYPOINT_SOURCE="${REPOSITORY_ROOT}/worker/voidaccess-entrypoint.sh"
readonly WORKER_ENV_SOURCE="${REPOSITORY_ROOT}/ops/voidaccess/worker.env"
readonly SYSUSERS_SOURCE="${REPOSITORY_ROOT}/ops/sysusers.d/swift-voidaccess.conf"
readonly TMPFILES_SOURCE="${REPOSITORY_ROOT}/ops/tmpfiles.d/swift-voidaccess.conf"
readonly UNIT_SOURCE="${REPOSITORY_ROOT}/ops/systemd/swift-vapor-voidaccess.service"

for command_name in awk chmod chown curl install ln mv rm sha256sum systemctl systemd-sysusers systemd-tmpfiles tar; do
    command -v "${command_name}" >/dev/null || {
        echo "Missing required command: ${command_name}" >&2
        exit 1
    }
done
[[ ${PYTHON_BIN} == /* && ${PYTHON_BIN} != / && -x ${PYTHON_BIN} ]] || {
    echo "VOIDACCESS_PYTHON_BIN must name a specific absolute Python 3.13 executable." >&2
    exit 1
}
[[ $("${PYTHON_BIN}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') == 3.13 ]] || {
    echo "VoidAccess requires Python 3.13; ${PYTHON_BIN} is a different version." >&2
    exit 1
}
for source_file in \
    "${REQUIREMENTS}" "${ADAPTER_SOURCE}" "${ENTRYPOINT_SOURCE}" "${WORKER_ENV_SOURCE}" \
    "${SYSUSERS_SOURCE}" "${TMPFILES_SOURCE}" "${UNIT_SOURCE}"; do
    [[ -f ${source_file} ]] || { echo "Missing repository file: ${source_file}" >&2; exit 1; }
done

install -d -m 0755 -o root -g root "${INSTALL_ROOT}" "${RELEASES_ROOT}"
systemd-sysusers "${SYSUSERS_SOURCE}"
systemd-tmpfiles --create "${TMPFILES_SOURCE}"

if [[ -e ${INSTALL_ROOT}/current && ! -L ${INSTALL_ROOT}/current ]]; then
    echo "Refusing to replace non-symlink ${INSTALL_ROOT}/current." >&2
    exit 1
fi

EXPECTED_REQUIREMENTS_SHA256="$(sha256sum "${REQUIREMENTS}" | awk '{print $1}')"
readonly EXPECTED_REQUIREMENTS_SHA256
if [[ -f ${RELEASE_DIR}/.complete ]]; then
    installed_commit="$(<"${RELEASE_DIR}/.source-commit")"
    installed_requirements="$(<"${RELEASE_DIR}/.requirements-sha256")"
    if [[ ${installed_commit} != "${VOIDACCESS_COMMIT}" || \
          ${installed_requirements} != "${EXPECTED_REQUIREMENTS_SHA256}" || \
          ! -x ${RELEASE_DIR}/venv/bin/voidaccess ]]; then
        echo "Existing release failed integrity checks: ${RELEASE_DIR}" >&2
        exit 1
    fi
else
    if [[ -e ${RELEASE_DIR} ]]; then
        echo "Incomplete release exists; inspect and remove only this path before retrying: ${RELEASE_DIR}" >&2
        exit 1
    fi

    DOWNLOAD_DIR="$(mktemp -d /tmp/swift-voidaccess-install.XXXXXX)"
    readonly DOWNLOAD_DIR
    cleanup() {
        rm -rf -- "${DOWNLOAD_DIR}"
    }
    trap cleanup EXIT

    readonly SOURCE_ARCHIVE="${DOWNLOAD_DIR}/voidaccess.tar.gz"
    readonly MODEL_WHEEL="${DOWNLOAD_DIR}/en_core_web_sm-${SPACY_MODEL_VERSION}-py3-none-any.whl"
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --retry 3 --retry-all-errors \
        "${VOIDACCESS_SOURCE_URL}" --output "${SOURCE_ARCHIVE}"
    printf '%s  %s\n' "${VOIDACCESS_SOURCE_SHA256}" "${SOURCE_ARCHIVE}" | sha256sum --check
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --retry 3 --retry-all-errors \
        "${SPACY_MODEL_URL}" --output "${MODEL_WHEEL}"
    printf '%s  %s\n' "${SPACY_MODEL_SHA256}" "${MODEL_WHEEL}" | sha256sum --check

    install -d -m 0755 -o root -g root "${RELEASE_DIR}"
    install -d -m 0755 -o root -g root "${RELEASE_DIR}/source"
    tar --extract --gzip --file "${SOURCE_ARCHIVE}" --directory "${RELEASE_DIR}/source" \
        --strip-components=1 --no-same-owner --no-same-permissions
    "${PYTHON_BIN}" -m venv "${RELEASE_DIR}/venv"
    "${RELEASE_DIR}/venv/bin/python" -m pip install \
        --disable-pip-version-check --require-hashes --requirement "${REQUIREMENTS}"
    "${RELEASE_DIR}/venv/bin/python" -m pip install \
        --disable-pip-version-check --no-deps "${MODEL_WHEEL}"
    "${RELEASE_DIR}/venv/bin/python" -m pip check
    install -m 0755 -o root -g root \
        "${ENTRYPOINT_SOURCE}" "${RELEASE_DIR}/venv/bin/voidaccess"
    "${RELEASE_DIR}/venv/bin/python" -c \
        "import sys, spacy; sys.path.insert(0, '${RELEASE_DIR}/source'); import voidaccess_cli; assert voidaccess_cli.__version__ == '${VOIDACCESS_VERSION}'; spacy.load('en_core_web_sm')"
    HOME="${DOWNLOAD_DIR}/smoke-home" \
        "${RELEASE_DIR}/venv/bin/voidaccess" --no-banner --help >/dev/null

    printf '%s\n' "${VOIDACCESS_COMMIT}" > "${RELEASE_DIR}/.source-commit"
    printf '%s\n' "${EXPECTED_REQUIREMENTS_SHA256}" > "${RELEASE_DIR}/.requirements-sha256"
    printf '%s\n' "${VOIDACCESS_VERSION}" > "${RELEASE_DIR}/.complete"
    chown -R root:root "${RELEASE_DIR}"
    chmod -R go-w "${RELEASE_DIR}"
fi

readonly NEXT_LINK="${INSTALL_ROOT}/.current.${VOIDACCESS_COMMIT}.$$"
ln -s "releases/${VOIDACCESS_COMMIT}" "${NEXT_LINK}"
mv -T "${NEXT_LINK}" "${INSTALL_ROOT}/current"

install -m 0755 -o root -g root "${ADAPTER_SOURCE}" "${ADAPTER_ROOT}/voidaccess_worker.py"
if [[ ! -e /etc/swift-voidaccess/worker.env ]]; then
    install -m 0640 -o root -g swift-voidaccess \
        "${WORKER_ENV_SOURCE}" /etc/swift-voidaccess/worker.env
fi
install -m 0644 -o root -g root "${SYSUSERS_SOURCE}" /etc/sysusers.d/swift-voidaccess.conf
install -m 0644 -o root -g root "${TMPFILES_SOURCE}" /etc/tmpfiles.d/swift-voidaccess.conf
install -m 0644 -o root -g root "${UNIT_SOURCE}" /etc/systemd/system/swift-vapor-voidaccess.service
systemctl daemon-reload

echo "VoidAccess ${VOIDACCESS_VERSION} staged at ${RELEASE_DIR}."
echo "No service was started and DARK_WEB_ENABLED was not changed."
echo "Complete the credential and canary steps in docs/DARK_WEB_OPERATIONS.md."
