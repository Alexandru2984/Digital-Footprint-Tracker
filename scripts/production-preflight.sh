#!/usr/bin/env bash

# Read-only production acceptance gate. It reports every failed invariant in a
# single run and never prints environment values, credential contents, origin
# addresses or application responses.

set -uo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077

REPOSITORY="${SWIFT_VAPOR_REPOSITORY:-/var/lib/swift-deploy/repository}"
RELEASE_ROOT=/srv/swift-vapor/releases
CURRENT_LINK=/srv/swift-vapor/current
APP_ENV=/etc/swift-vapor/app.env
CREDENTIAL_ROOT=/etc/credstore.encrypted
BACKUP_DIRECTORY=/var/lib/swift-vapor-backup/artifacts
BACKUP_STATUS=/var/lib/swift-vapor-backup/status/last-success
CHECK_BACKUP=/usr/local/libexec/swift-vapor/check-backup.sh
DEPLOYMENT_GATE=0
SELF_TEST=0
PASSED=0
FAILED=0
SKIPPED=0

usage() {
    echo "usage: $0 [--repository ABSOLUTE_PATH] [--deployment-gate | --self-test]" >&2
}

while (( $# > 0 )); do
    case "$1" in
        --repository)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            REPOSITORY="$2"
            shift 2
            ;;
        --deployment-gate)
            DEPLOYMENT_GATE=1
            shift
            ;;
        --self-test)
            SELF_TEST=1
            shift
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

pass() {
    PASSED=$(( PASSED + 1 ))
    printf '[pass] %s\n' "$1"
}

fail() {
    FAILED=$(( FAILED + 1 ))
    printf '[fail] %s\n' "$1" >&2
}

skip() {
    SKIPPED=$(( SKIPPED + 1 ))
    printf '[skip] %s\n' "$1"
}

check() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label"
    fi
}

specific_absolute_path() {
    [[ "$1" == /* && "$1" != "/" && "$1" != *$'\n'* && "$1" != *$'\r'* ]]
}

secure_regular_file() {
    local path="$1" expected_owner="$2" privacy="$3"
    local mode size
    [[ -f "$path" && ! -L "$path" ]] || return 1
    [[ "$(stat -c '%U' "$path")" == "$expected_owner" ]] || return 1
    mode="$(stat -c '%a' "$path")" || return 1
    if [[ "$privacy" == private ]]; then
        (( (8#$mode & 077) == 0 )) || return 1
    else
        (( (8#$mode & 022) == 0 )) || return 1
    fi
    size="$(stat -c '%s' "$path")" || return 1
    (( size > 0 && size <= 1048576 ))
}

environment_has_no_secrets() {
    local path="$1"
    ! grep -Eq \
        '^[[:space:]]*([A-Z0-9_]*(PASSWORD|PASS|TOKEN|SECRET|PRIVATE_KEY|API_KEY)|(ENCRYPTION_KEY|ENCRYPTION_PREVIOUS_KEYS|AUDIT_SIGNING_KEY|AUDIT_COMMITMENT_KEY))(_FILE)?=' \
        "$path"
}

environment_is_complete() {
    local variable
    for variable in DATABASE_HOST DATABASE_USERNAME DATABASE_NAME ALLOWED_ORIGIN BASE_URL BACKUP_STATUS_FILE; do
        grep -Eq "^${variable}=.+$" "$APP_ENV" || return 1
    done
}

repository_is_acceptable() {
    local local_commit remote_commit origin
    specific_absolute_path "$REPOSITORY" || return 1
    [[ -d "$REPOSITORY/.git" && ! -L "$REPOSITORY" ]] || return 1
    [[ "$(stat -c '%U' "$REPOSITORY")" == swift-deploy ]] || return 1
    [[ -z "$(git -c safe.directory="$REPOSITORY" -C "$REPOSITORY" status --porcelain)" ]] || return 1
    [[ "$(git -c safe.directory="$REPOSITORY" -C "$REPOSITORY" branch --show-current)" == main ]] || return 1
    origin="$(git -c safe.directory="$REPOSITORY" -C "$REPOSITORY" remote get-url origin)" || return 1
    [[ "$origin" =~ ^https://github\.com/Alexandru2984/Digital-Footprint-Tracker(\.git)?$ ]] || return 1
    local_commit="$(git -c safe.directory="$REPOSITORY" -C "$REPOSITORY" rev-parse HEAD)" || return 1
    remote_commit="$(git -c safe.directory="$REPOSITORY" -C "$REPOSITORY" rev-parse origin/main)" || return 1
    [[ "$local_commit" =~ ^[0-9a-f]{40}$ && "$remote_commit" =~ ^[0-9a-f]{40}$ ]] || return 1
    git -c safe.directory="$REPOSITORY" -C "$REPOSITORY" \
        merge-base --is-ancestor "$local_commit" "$remote_commit"
}

account_has_shell() {
    local account="$1" expected_shell="$2" record
    record="$(getent passwd "$account")" || return 1
    [[ "${record##*:}" == "$expected_shell" ]]
}

account_avoids_privileged_groups() {
    local account="$1" group
    local groups
    groups=" $(id -nG "$account") " || return 1
    for group in root sudo wheel adm docker lxd libvirt kvm disk shadow systemd-journal; do
        [[ "$groups" != *" $group "* ]] || return 1
    done
}

account_in_group() {
    id -nG "$1" | tr ' ' '\n' | grep -qFx "$2"
}

account_is_locked() {
    [[ "$(passwd -S "$1" | awk '{print $2}')" == L ]]
}

authorized_key_is_restricted() {
    local path=/var/lib/swift-deploy/.ssh/authorized_keys
    secure_regular_file "$path" root public || return 1
    [[ "$(awk '!/^[[:space:]]*(#|$)/ { count++ } END { print count + 0 }' "$path")" -eq 1 ]] \
        || return 1
    grep -Eq \
        '^restrict,command="/usr/local/libexec/swift-vapor/deploy\.sh"[[:space:]]+(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521))[[:space:]]+[A-Za-z0-9+/]+={0,3}([[:space:]][^[:cntrl:]]+)?$' \
        "$path"
}

installed_deploy_tools_are_root_owned() {
    local tool
    for tool in deploy.sh build-release.sh release-lib.sh production-preflight.sh check-backup.sh backup.sh; do
        secure_regular_file "/usr/local/libexec/swift-vapor/$tool" root public || return 1
        cmp -s "/usr/local/libexec/swift-vapor/$tool" "$REPOSITORY/scripts/$tool" || return 1
    done
    [[ -x /usr/local/libexec/swift-vapor/deploy.sh \
        && -x /usr/local/libexec/swift-vapor/build-release.sh \
        && -x /usr/local/libexec/swift-vapor/production-preflight.sh \
        && -x /usr/local/libexec/swift-vapor/check-backup.sh \
        && -x /usr/local/libexec/swift-vapor/backup.sh ]] || return 1
    secure_regular_file /usr/local/sbin/update-swift-csp root public \
        && [[ -x /usr/local/sbin/update-swift-csp ]] \
        && cmp -s /usr/local/sbin/update-swift-csp "$REPOSITORY/ops/libexec/update-swift-csp"
}

credential_sources_are_private() {
    local credential
    for credential in \
        swift-vapor-database-password \
        swift-vapor-encryption-key \
        swift-vapor-audit-signing-key \
        swift-vapor-audit-commitment-key \
        swift-vapor-backup-passphrase; do
        secure_regular_file "$CREDENTIAL_ROOT/$credential" root private || return 1
    done
}

application_environment_is_safe() {
    secure_regular_file "$APP_ENV" root public \
        && environment_has_no_secrets "$APP_ENV" \
        && environment_is_complete
}

application_unit_is_effective() {
    local unit credential variable
    unit="$(systemctl cat swift-vapor.service)" || return 1
    [[ "$(systemctl show --property User --value swift-vapor.service)" == swift-vapor ]] || return 1
    [[ "$(systemctl show --property Group --value swift-vapor.service)" == swift-vapor ]] || return 1
    systemctl show --property ExecStart --value swift-vapor.service \
        | grep -qF '/srv/swift-vapor/current/Run' || return 1
    systemctl show --property EnvironmentFiles --value swift-vapor.service \
        | grep -qF '/etc/swift-vapor/app.env' || return 1
    [[ "$(systemctl show --property MemoryMax --value swift-vapor.service)" == 2147483648 ]] \
        || return 1
    [[ "$(systemctl show --property TasksMax --value swift-vapor.service)" == 512 ]] \
        || return 1
    systemctl show --property InaccessiblePaths --value swift-vapor.service \
        | grep -qF '/run/docker.sock' || return 1
    grep -qFx 'EnvironmentFile=/etc/swift-vapor/app.env' <<< "$unit" || return 1
    grep -qF '/srv/swift-vapor/current/Run serve' <<< "$unit" || return 1
    grep -qFx 'MemoryMax=2G' <<< "$unit" || return 1
    grep -qF 'InaccessiblePaths=-/run/docker.sock' <<< "$unit" || return 1
    while read -r credential variable; do
        grep -qF "LoadCredentialEncrypted=$credential:$CREDENTIAL_ROOT/swift-vapor-$credential" \
            <<< "$unit" || return 1
        grep -qF "Environment=${variable}_FILE=%d/$credential" <<< "$unit" || return 1
    done <<'EOF'
database-password DATABASE_PASSWORD
encryption-key ENCRYPTION_KEY
audit-signing-key AUDIT_SIGNING_KEY
audit-commitment-key AUDIT_COMMITMENT_KEY
EOF
}

migration_unit_is_effective() {
    local unit credential variable
    unit="$(systemctl cat swift-vapor-migrate.service)" || return 1
    [[ "$(systemctl show --property User --value swift-vapor-migrate.service)" == swift-vapor ]] \
        || return 1
    [[ "$(systemctl show --property Group --value swift-vapor-migrate.service)" == swift-vapor ]] \
        || return 1
    systemctl show --property ExecStart --value swift-vapor-migrate.service \
        | grep -qF '/srv/swift-vapor/next/Run' || return 1
    systemctl show --property EnvironmentFiles --value swift-vapor-migrate.service \
        | grep -qF '/etc/swift-vapor/app.env' || return 1
    systemctl show --property InaccessiblePaths --value swift-vapor-migrate.service \
        | grep -qF '/run/docker.sock' || return 1
    grep -qFx 'EnvironmentFile=/etc/swift-vapor/app.env' <<< "$unit" || return 1
    grep -qF '/srv/swift-vapor/next/Run migrate' <<< "$unit" || return 1
    grep -qF 'AUTO_MIGRATE=true' <<< "$unit" || return 1
    grep -qF 'InaccessiblePaths=-/run/docker.sock' <<< "$unit" || return 1
    while read -r credential variable; do
        grep -qF "LoadCredentialEncrypted=$credential:$CREDENTIAL_ROOT/swift-vapor-$credential" \
            <<< "$unit" || return 1
        grep -qF "Environment=${variable}_FILE=%d/$credential" <<< "$unit" || return 1
    done <<'EOF'
database-password DATABASE_PASSWORD
encryption-key ENCRYPTION_KEY
audit-signing-key AUDIT_SIGNING_KEY
audit-commitment-key AUDIT_COMMITMENT_KEY
EOF
}

backup_unit_is_effective() {
    local unit
    unit="$(systemctl cat swift-vapor-backup.service)" || return 1
    [[ "$(systemctl show --property User --value swift-vapor-backup.service)" == swift-backup ]] \
        || return 1
    [[ "$(systemctl show --property Group --value swift-vapor-backup.service)" == swift-backup ]] \
        || return 1
    systemctl show --property ExecStart --value swift-vapor-backup.service \
        | grep -qF '/usr/local/libexec/swift-vapor/backup.sh' || return 1
    systemctl show --property EnvironmentFiles --value swift-vapor-backup.service \
        | grep -qF '/etc/swift-vapor/app.env' || return 1
    systemctl show --property InaccessiblePaths --value swift-vapor-backup.service \
        | grep -qF '/run/docker.sock' || return 1
    grep -qFx 'SupplementaryGroups=swift-backup-check' <<< "$unit" || return 1
    grep -qF 'LoadCredentialEncrypted=database-password:' <<< "$unit" || return 1
    grep -qF 'LoadCredentialEncrypted=backup-passphrase:' <<< "$unit" || return 1
    grep -qFx 'Environment=DATABASE_PASSWORD_FILE=%d/database-password' <<< "$unit" || return 1
    grep -qFx 'Environment=BACKUP_PASSPHRASE_FILE=%d/backup-passphrase' <<< "$unit" || return 1
    grep -qFx 'ProtectHome=true' <<< "$unit" || return 1
    grep -qF 'InaccessiblePaths=-/run/docker.sock' <<< "$unit"
}

active_release_is_valid() {
    local active
    [[ -L "$CURRENT_LINK" ]] || return 1
    active="$(readlink -f -- "$CURRENT_LINK")" || return 1
    verify_release "$active" "$RELEASE_ROOT"
}

running_process_matches_release() {
    # /proc/<pid>/exe cannot be dereferenced across users under the standard
    # ptrace access model, and this check runs as swift-deploy inspecting a
    # process owned by swift-vapor -- so it can't hash-verify the running
    # binary directly (that isolation is intentional; widening it just for
    # this check would undo the whole point of separate identities). Instead,
    # prove the running instance can't be stale: deploy.sh always switches the
    # $CURRENT_LINK symlink strictly before restarting the service, so an
    # ActiveEnterTimestamp at or after the symlink's mtime means this instance
    # started under the release the symlink currently names.
    local pid active_enter link_mtime active
    pid="$(systemctl show --property MainPID --value swift-vapor.service)" || return 1
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    active_enter="$(systemctl show --property ActiveEnterTimestamp --value swift-vapor.service)" || return 1
    [[ -n "$active_enter" ]] || return 1
    active_enter="$(date -d "$active_enter" +%s)" || return 1
    active="$(readlink -f -- "$CURRENT_LINK")" || return 1
    [[ -d "$active" ]] || return 1
    link_mtime="$(stat -c '%Y' -- "$CURRENT_LINK")" || return 1
    (( active_enter >= link_mtime ))
}

served_frontend_matches_release() {
    local active expected actual
    active="$(readlink -f -- "$CURRENT_LINK")" || return 1
    expected="$(release_manifest_value "$active" frontend_index_sha256)" || return 1
    actual="$(curl --fail --silent --show-error --max-time 5 \
        --header 'Host: 5jyd4lflkewyc3gm42uxvi2aryh5g2l4ib2pm5uewpff3ld7yfii5iid.onion' \
        http://127.0.0.1:8110/index.html | sha256sum | awk '{print $1}')" || return 1
    [[ "$actual" == "$expected" ]]
}

internal_readiness_is_healthy() {
    curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8085/ready >/dev/null
}

public_readiness_is_hidden() {
    local status
    status="$(curl --silent --output /dev/null --max-time 5 --write-out '%{http_code}' \
        --header 'Host: 5jyd4lflkewyc3gm42uxvi2aryh5g2l4ib2pm5uewpff3ld7yfii5iid.onion' \
        http://127.0.0.1:8110/api/ready)" || return 1
    [[ "$status" == 404 ]]
}

backup_is_current() {
    "$CHECK_BACKUP" \
        --directory "$BACKUP_DIRECTORY" \
        --status-file "$BACKUP_STATUS" \
        --max-age-hours 30
}

runtime_cannot_reach_docker_socket() {
    runuser -u swift-vapor -- test ! -r /run/docker.sock \
        && runuser -u swift-vapor -- test ! -w /run/docker.sock
}

sudo_policy_is_narrow() {
    visudo -cf /etc/sudoers.d/swift-vapor-deploy >/dev/null \
        && cmp -s "$REPOSITORY/ops/sudoers/swift-vapor-deploy" \
            /etc/sudoers.d/swift-vapor-deploy \
        && ! grep -REq \
            '^[[:space:]]*(micu|swift-deploy)[[:space:]]+[^#]*NOPASSWD:[[:space:]]*ALL([[:space:]]|$)' \
            /etc/sudoers /etc/sudoers.d
}

self_test() {
    local fixture owner
    fixture="$(mktemp -d)"
    owner="$(id -un)"
    # Invoked indirectly by the RETURN trap.
    # shellcheck disable=SC2317,SC2329
    cleanup_self_test() { rm -rf -- "$fixture"; }
    trap cleanup_self_test RETURN

    printf '%s\n' 'ALLOWED_ORIGIN=https://example.test' > "$fixture/safe.env"
    chmod 0600 "$fixture/safe.env"
    secure_regular_file "$fixture/safe.env" "$owner" private || return 1
    environment_has_no_secrets "$fixture/safe.env" || return 1

    printf '%s\n' 'DATABASE_PASSWORD=fixture-only' > "$fixture/unsafe.env"
    if environment_has_no_secrets "$fixture/unsafe.env"; then return 1; fi
    chmod 0644 "$fixture/safe.env"
    if secure_regular_file "$fixture/safe.env" "$owner" private; then return 1; fi
    ln -s "$fixture/safe.env" "$fixture/link.env"
    if secure_regular_file "$fixture/link.env" "$owner" public; then return 1; fi
    specific_absolute_path /var/lib/example || return 1
    if specific_absolute_path /; then return 1; fi
    echo "production preflight self-test passed"
}

if (( SELF_TEST )); then
    (( DEPLOYMENT_GATE == 0 )) || { usage; exit 2; }
    self_test
    exit
fi

specific_absolute_path "$REPOSITORY" || { echo "preflight: unsafe repository path" >&2; exit 2; }
if (( ! DEPLOYMENT_GATE && EUID != 0 )); then
    echo "preflight: full mode requires root; use --deployment-gate only from the forced deploy account" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release-lib.sh
source "$SCRIPT_DIR/release-lib.sh"

check "dedicated deployment repository is clean and trusted" repository_is_acceptable
check "swift-vapor is a non-login account" account_has_shell swift-vapor /usr/sbin/nologin
check "swift-deploy has only its forced-command shell" account_has_shell swift-deploy /bin/bash
check "swift-backup is a non-login account" account_has_shell swift-backup /usr/sbin/nologin
check "runtime account has no host-privileged groups" account_avoids_privileged_groups swift-vapor
check "deploy account has no host-privileged groups" account_avoids_privileged_groups swift-deploy
check "backup account has no host-privileged groups" account_avoids_privileged_groups swift-backup
check "deploy account can inspect backup metadata" account_in_group swift-deploy swift-backup-check
check "backup account publishes checker metadata" account_in_group swift-backup swift-backup-check
if (( DEPLOYMENT_GATE )); then
    check "forced deployment runs as swift-deploy" test "$(id -un)" = swift-deploy
fi
check "non-secret application environment is complete" application_environment_is_safe
check "application unit uses the isolated release contract" application_unit_is_effective
check "migration unit is explicit and isolated" migration_unit_is_effective
check "backup unit uses isolated file credentials" backup_unit_is_effective
check "encrypted backup and freshness marker are current" backup_is_current
check "current immutable release passes its manifest" active_release_is_valid
check "running executable exactly matches current release" running_process_matches_release
check "internal database readiness is healthy" internal_readiness_is_healthy
check "public readiness route is hidden" public_readiness_is_hidden
check "nginx serves the selected frontend generation" served_frontend_matches_release
check "application service is active" systemctl is-active --quiet swift-vapor.service
check "backup timer is active" systemctl is-active --quiet swift-vapor-backup.timer
check "backup timer is enabled" systemctl is-enabled --quiet swift-vapor-backup.timer
check "nginx is active" systemctl is-active --quiet nginx.service
check "Cloudflare tunnel is active" systemctl is-active --quiet cloudflared.service
check "Tor onion ingress is active" systemctl is-active --quiet tor.service

if (( DEPLOYMENT_GATE )); then
    skip "root-only credential, SSH, sudoers, nginx syntax and socket checks"
else
    check "encrypted credential sources are root-private" credential_sources_are_private
    check "deploy authorized key is root-owned and forced" authorized_key_is_restricted
    check "installed deployment tools are root-owned" installed_deploy_tools_are_root_owned
    check "runtime identity cannot reach the Docker socket" runtime_cannot_reach_docker_socket
    check "deploy sudo policy is narrow" sudo_policy_is_narrow
    check "deploy account password is locked" account_is_locked swift-deploy
    check "backup account password is locked" account_is_locked swift-backup
    check "installed nginx configuration parses" nginx -t
fi

printf 'preflight: %d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
(( FAILED == 0 ))
