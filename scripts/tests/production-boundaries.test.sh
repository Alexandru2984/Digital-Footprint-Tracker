#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLEARNET="$ROOT_DIR/ops/nginx/swift.micutu.com"
ONION="$ROOT_DIR/ops/nginx/swift-onion.conf"
REALIP="$ROOT_DIR/ops/nginx/conf.d/cloudflare-realip.conf"
GENERATOR="$ROOT_DIR/scripts/update-cloudflare-ips.sh"
HARDENING="$ROOT_DIR/ops/systemd/swift-vapor.service.d/10-hardening.conf"
SERVICE="$ROOT_DIR/ops/systemd/swift-vapor.service"
MIGRATION="$ROOT_DIR/ops/systemd/swift-vapor-migrate.service"
WORKER="$ROOT_DIR/ops/systemd/swift-vapor-voidaccess.service"
ENVIRONMENT="$ROOT_DIR/ops/environment/swift-vapor.env.example"
SYSUSERS="$ROOT_DIR/ops/sysusers.d/swift-vapor.conf"
TMPFILES="$ROOT_DIR/ops/tmpfiles.d/swift-vapor.conf"
SUDOERS="$ROOT_DIR/ops/sudoers/swift-vapor-deploy"
DARK_WEB_DROPIN="$ROOT_DIR/ops/systemd/swift-vapor.service.d/30-dark-web-credential.conf.example"
OPTIONAL_DROPIN="$ROOT_DIR/ops/systemd/swift-vapor.service.d/40-optional-credentials.conf.example"
ADMIN_DROPIN="$ROOT_DIR/ops/systemd/swift-vapor-migrate.service.d/30-admin-bootstrap-credential.conf.example"
BACKUP_SERVICE="$ROOT_DIR/ops/systemd/swift-vapor-backup.service"
BACKUP_TIMER="$ROOT_DIR/ops/systemd/swift-vapor-backup.timer"
BACKUP_SYSUSERS="$ROOT_DIR/ops/sysusers.d/swift-vapor-backup.conf"
BACKUP_TMPFILES="$ROOT_DIR/ops/tmpfiles.d/swift-vapor-backup.conf"

[[ ! -e "$ROOT_DIR/scripts/swift-vapor-backup.service" ]]
[[ ! -e "$ROOT_DIR/scripts/swift-vapor-backup.timer" ]]

for vhost in "$CLEARNET" "$ONION"; do
    grep -Eq '^[[:space:]]*location = /ready[[:space:]]*\{ return 404; \}$' "$vhost"
    grep -Eq '^[[:space:]]*location = /api/ready[[:space:]]*\{ return 404; \}$' "$vhost"
done

# Real-IP trust is global. A second server-level list can shadow the generated
# policy and silently collapse all Cloudflare Tunnel clients onto loopback.
if grep -qF 'include snippets/cloudflare-realip.conf;' "$CLEARNET"; then
    echo "clearnet vhost must not override the global real-IP policy" >&2
    exit 1
fi

for source in "$REALIP" "$GENERATOR"; do
    grep -qF 'set_real_ip_from 127.0.0.1;' "$source"
    grep -qF 'set_real_ip_from ::1;' "$source"
done
[[ "$(grep -c '^real_ip_header CF-Connecting-IP;$' "$REALIP")" -eq 1 ]]

socket_barrier='InaccessiblePaths=-/run/docker.sock -/run/containerd/containerd.sock -/run/podman/podman.sock'
for unit in "$HARDENING" "$MIGRATION" "$WORKER"; do
    grep -qFx "$socket_barrier" "$unit"
done

grep -qFx 'ProtectHome=true' "$HARDENING"
grep -qFx 'PrivateDevices=yes' "$HARDENING"
grep -qFx 'CapabilityBoundingSet=' "$HARDENING"
grep -qFx 'MemoryMax=2G' "$HARDENING"
grep -qFx 'TasksMax=512' "$HARDENING"

for unit in "$SERVICE" "$MIGRATION"; do
    grep -qFx 'User=swift-vapor' "$unit"
    grep -qFx 'Group=swift-vapor' "$unit"
    grep -qFx 'EnvironmentFile=/etc/swift-vapor/app.env' "$unit"
    if grep -qF '/home/micu/' "$unit"; then
        echo "application units must not depend on a personal home" >&2
        exit 1
    fi
done

while read -r credential variable encrypted_source; do
    for unit in "$SERVICE" "$MIGRATION"; do
        grep -qFx "LoadCredentialEncrypted=$credential:$encrypted_source" "$unit"
        grep -qFx "Environment=${variable}_FILE=%d/$credential" "$unit"
    done
done <<'EOF'
database-password DATABASE_PASSWORD /etc/credstore.encrypted/swift-vapor-database-password
encryption-key ENCRYPTION_KEY /etc/credstore.encrypted/swift-vapor-encryption-key
audit-signing-key AUDIT_SIGNING_KEY /etc/credstore.encrypted/swift-vapor-audit-signing-key
audit-commitment-key AUDIT_COMMITMENT_KEY /etc/credstore.encrypted/swift-vapor-audit-commitment-key
EOF

grep -qF 'u      swift-vapor ' "$SYSUSERS"
grep -qF 'u      swift-deploy ' "$SYSUSERS"
grep -Eq '^d[[:space:]]+/var/lib/swift-deploy[[:space:]]+0755[[:space:]]+root[[:space:]]+root[[:space:]]' "$TMPFILES"
grep -Eq '^d[[:space:]]+/var/lib/swift-deploy/\.ssh[[:space:]]+0755[[:space:]]+root[[:space:]]+root[[:space:]]' "$TMPFILES"
grep -Eq '^d[[:space:]]+/var/lib/swift-deploy/repository[[:space:]]+0700[[:space:]]+swift-deploy[[:space:]]+swift-deploy[[:space:]]' "$TMPFILES"
grep -Eq '^d[[:space:]]+/srv/swift-vapor[[:space:]]+0755[[:space:]]+swift-deploy[[:space:]]+swift-deploy[[:space:]]' "$TMPFILES"
grep -qF 'swift-deploy ALL=(root) NOPASSWD: SWIFT_VAPOR_DEPLOY' "$SUDOERS"
if grep -Eq '^[[:space:]]*micu[[:space:]]+ALL=' "$SUDOERS"; then
    echo "personal account must not retain deploy sudo authority" >&2
    exit 1
fi

grep -qF "BUILD_RELEASE=\"\$SCRIPT_DIR/build-release.sh\"" "$ROOT_DIR/scripts/deploy.sh"
if grep -qF "\$REPOSITORY/scripts/build-release.sh" "$ROOT_DIR/scripts/deploy.sh"; then
    echo "deploy must execute the root-installed release builder" >&2
    exit 1
fi

for example in "$DARK_WEB_DROPIN" "$OPTIONAL_DROPIN" "$ADMIN_DROPIN"; do
    [[ "$example" == *.conf.example ]]
    grep -qF 'LoadCredentialEncrypted=' "$example"
done

if grep -Eq '^[[:space:]]*(DATABASE_PASSWORD|ENCRYPTION_KEY|ENCRYPTION_PREVIOUS_KEYS|AUDIT_SIGNING_KEY|AUDIT_COMMITMENT_KEY|ADMIN_PASSWORD|SMTP_PASS|METRICS_TOKEN|DARK_WEB_SHARED_SECRET|[A-Z0-9_]*API_KEY)=' "$ENVIRONMENT"; then
    echo "non-secret environment template contains a secret assignment" >&2
    exit 1
fi

grep -qFx 'User=swift-backup' "$BACKUP_SERVICE"
grep -qFx 'Group=swift-backup' "$BACKUP_SERVICE"
grep -qFx 'SupplementaryGroups=swift-backup-check' "$BACKUP_SERVICE"
grep -qFx 'EnvironmentFile=/etc/swift-vapor/app.env' "$BACKUP_SERVICE"
grep -qFx 'LoadCredentialEncrypted=database-password:/etc/credstore.encrypted/swift-vapor-database-password' "$BACKUP_SERVICE"
grep -qFx 'LoadCredentialEncrypted=backup-passphrase:/etc/credstore.encrypted/swift-vapor-backup-passphrase' "$BACKUP_SERVICE"
grep -qFx 'Environment=DATABASE_PASSWORD_FILE=%d/database-password' "$BACKUP_SERVICE"
grep -qFx 'Environment=BACKUP_PASSPHRASE_FILE=%d/backup-passphrase' "$BACKUP_SERVICE"
grep -qFx 'ProtectHome=true' "$BACKUP_SERVICE"
grep -qFx "$socket_barrier" "$BACKUP_SERVICE"
grep -qFx 'Persistent=true' "$BACKUP_TIMER"
if grep -qF '/home/micu/' "$BACKUP_SERVICE"; then
    echo "backup unit must not depend on a personal home" >&2
    exit 1
fi
grep -Eq '^u![[:space:]]+swift-backup[[:space:]]' "$BACKUP_SYSUSERS"
grep -Eq '^m[[:space:]]+swift-backup[[:space:]]+swift-backup-check$' "$BACKUP_SYSUSERS"
grep -Eq '^m[[:space:]]+swift-deploy[[:space:]]+swift-backup-check$' "$BACKUP_SYSUSERS"
grep -Eq '^d[[:space:]]+/var/lib/swift-vapor-backup/artifacts[[:space:]]+0750[[:space:]]+swift-backup[[:space:]]+swift-backup-check[[:space:]]' "$BACKUP_TMPFILES"
grep -Eq '^d[[:space:]]+/var/lib/swift-vapor-backup/status[[:space:]]+0755[[:space:]]+swift-backup[[:space:]]+swift-backup[[:space:]]' "$BACKUP_TMPFILES"

echo "production boundary tests passed"
