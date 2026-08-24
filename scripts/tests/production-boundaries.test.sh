#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLEARNET="$ROOT_DIR/ops/nginx/swift.micutu.com"
ONION="$ROOT_DIR/ops/nginx/swift-onion.conf"
REALIP="$ROOT_DIR/ops/nginx/conf.d/cloudflare-realip.conf"
GENERATOR="$ROOT_DIR/scripts/update-cloudflare-ips.sh"
HARDENING="$ROOT_DIR/ops/systemd/swift-vapor.service.d/10-hardening.conf"
MIGRATION="$ROOT_DIR/ops/systemd/swift-vapor-migrate.service"
WORKER="$ROOT_DIR/ops/systemd/swift-vapor-voidaccess.service"

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

echo "production boundary tests passed"
