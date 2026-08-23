#!/usr/bin/env bash
#
# Regenerates both the nginx `real_ip` trust list and the origin-guard geo map
# from Cloudflare's published ranges.
#
# Why this exists: port 443 on the origin is reachable directly (not only via
# Cloudflare). Without a real_ip trust list, nginx forwards a client-supplied
# `CF-Connecting-IP` header verbatim, letting anyone who hits the origin directly
# spoof their source IP — defeating per-IP rate limiting and audit attribution.
# With this snippet, nginx overwrites $remote_addr from CF-Connecting-IP ONLY for
# connections whose peer is in a Cloudflare range; a direct attacker's forged
# header is ignored and their real peer IP stands.
#
# Idempotent: validates both generated files and reloads only on change. Both
# files are rolled back if validation or reload fails. `--check` performs no
# writes and exits non-zero when either installed file is stale.

set -euo pipefail
umask 077

# NOTE: this must be a path nginx actually loads. nginx.conf includes
# conf.d/*.conf but NOT snippets/, and no vhost includes the snippet, so the
# old snippets/ default meant this timer refreshed a file nobody read while the
# live ranges in conf.d/ silently went stale.
REALIP_SNIPPET="${CF_REALIP_SNIPPET:-${CF_SNIPPET:-/etc/nginx/conf.d/cloudflare-realip.conf}}"
ORIGIN_GUARD="${CF_ORIGIN_GUARD:-/etc/nginx/conf.d/cloudflare-origin-guard.conf}"
CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then
    CHECK_ONLY=1
elif [[ $# -ne 0 ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
fi

V4="$(curl -fsS --max-time 15 https://www.cloudflare.com/ips-v4)" || { echo "[cf] failed to fetch ips-v4" >&2; exit 1; }
V6="$(curl -fsS --max-time 15 https://www.cloudflare.com/ips-v6)" || { echo "[cf] failed to fetch ips-v6" >&2; exit 1; }
CIDRS="$(mktemp)"
REALIP_TMP="$(mktemp)"
GUARD_TMP="$(mktemp)"
BACKUP_DIR=""
cleanup() {
    rm -f "$CIDRS" "$REALIP_TMP" "$GUARD_TMP"
    if [[ -n "$BACKUP_DIR" ]]; then
        sudo rm -f "$BACKUP_DIR/realip" "$BACKUP_DIR/guard"
        rmdir "$BACKUP_DIR" 2>/dev/null || true
    fi
}
trap cleanup EXIT

printf '%s\n%s\n' "$V4" "$V6" | sed '/^[[:space:]]*$/d' > "$CIDRS"

# Reject empty, truncated, wrong-family, or syntactically hostile responses
# before interpolating remote data into nginx configuration.
python3 - "$CIDRS" <<'PY'
import ipaddress
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="ascii").splitlines()
networks = [ipaddress.ip_network(line, strict=True) for line in lines]
if len(networks) != len(set(networks)):
    raise SystemExit("[cf] duplicate network in response")
v4 = sum(network.version == 4 for network in networks)
v6 = sum(network.version == 6 for network in networks)
if v4 < 10 or v6 < 5:
    raise SystemExit(f"[cf] implausible response ({v4} IPv4, {v6} IPv6 ranges)")
PY

{
    echo "# Managed by scripts/update-cloudflare-ips.sh — do not edit by hand."
    echo "# Trust CF-Connecting-IP only from Cloudflare edge peers (anti-spoofing)."
    echo "# Loopback is trusted as well: cloudflared terminates the Cloudflare Tunnel"
    echo "# on this host and connects to nginx from 127.0.0.1. Without these two lines"
    echo "# every tunnelled request logs as 127.0.0.1 and shares a single rate-limit"
    echo "# key, which would neuter the per-IP limits on nim/prolog and mislead"
    echo "# fail2ban into banning loopback."
    echo "set_real_ip_from 127.0.0.1;"
    echo "set_real_ip_from ::1;"
    while IFS= read -r cidr; do echo "set_real_ip_from $cidr;"; done < "$CIDRS"
    echo "real_ip_header CF-Connecting-IP;"
} > "$REALIP_TMP"

{
    echo "# Managed by scripts/update-cloudflare-ips.sh — do not edit by hand."
    echo "# The peer address is captured before ngx_http_realip_module replaces"
    # nginx variables must remain literal in the generated configuration.
    # shellcheck disable=SC2016
    echo '# $remote_addr with CF-Connecting-IP.'
    # shellcheck disable=SC2016
    echo 'geo $realip_remote_addr $from_cloudflare_origin {'
    echo "    default 0;"
    echo "    127.0.0.1/32 1;"
    echo "    ::1/128 1;"
    while IFS= read -r cidr; do echo "    $cidr 1;"; done < "$CIDRS"
    echo "}"
} > "$GUARD_TMP"

realip_current=0
guard_current=0
[[ -f "$REALIP_SNIPPET" ]] && cmp -s "$REALIP_TMP" "$REALIP_SNIPPET" && realip_current=1
[[ -f "$ORIGIN_GUARD" ]] && cmp -s "$GUARD_TMP" "$ORIGIN_GUARD" && guard_current=1

if [[ "$realip_current" -eq 1 && "$guard_current" -eq 1 ]]; then
    echo "[cf] already up to date ($(grep -c set_real_ip_from "$REALIP_SNIPPET") ranges)"
    exit 0
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    [[ "$realip_current" -eq 1 ]] || echo "[cf] stale: $REALIP_SNIPPET" >&2
    [[ "$guard_current" -eq 1 ]] || echo "[cf] stale: $ORIGIN_GUARD" >&2
    exit 1
fi

BACKUP_DIR="$(mktemp -d)"
realip_existed=0
guard_existed=0
if [[ -f "$REALIP_SNIPPET" ]]; then
    sudo cp -a "$REALIP_SNIPPET" "$BACKUP_DIR/realip"
    realip_existed=1
fi
if [[ -f "$ORIGIN_GUARD" ]]; then
    sudo cp -a "$ORIGIN_GUARD" "$BACKUP_DIR/guard"
    guard_existed=1
fi
sudo install -o root -g root -m 0644 "$REALIP_TMP" "$REALIP_SNIPPET"
sudo install -o root -g root -m 0644 "$GUARD_TMP" "$ORIGIN_GUARD"

rollback() {
    if [[ "$realip_existed" -eq 1 ]]; then sudo cp -a "$BACKUP_DIR/realip" "$REALIP_SNIPPET"; else sudo rm -f "$REALIP_SNIPPET"; fi
    if [[ "$guard_existed" -eq 1 ]]; then sudo cp -a "$BACKUP_DIR/guard" "$ORIGIN_GUARD"; else sudo rm -f "$ORIGIN_GUARD"; fi
}

if ! sudo nginx -t; then
    echo "[cf] nginx validation failed — rolling back both files" >&2
    rollback
    exit 1
fi
if ! sudo systemctl reload nginx; then
    echo "[cf] nginx reload failed — rolling back both files" >&2
    rollback
    sudo nginx -t && sudo systemctl reload nginx || true
    exit 1
fi
echo "[cf] real-IP and origin-guard files updated ($(grep -c set_real_ip_from "$REALIP_SNIPPET") ranges)"
