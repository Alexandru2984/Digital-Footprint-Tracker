#!/usr/bin/env bash
#
# Regenerates the nginx `real_ip` trust list for Cloudflare from Cloudflare's
# published ranges, so the origin only accepts a client IP from CF-Connecting-IP
# when the TCP peer is actually a Cloudflare edge.
#
# Why this exists: port 443 on the origin is reachable directly (not only via
# Cloudflare). Without a real_ip trust list, nginx forwards a client-supplied
# `CF-Connecting-IP` header verbatim, letting anyone who hits the origin directly
# spoof their source IP — defeating per-IP rate limiting and audit attribution.
# With this snippet, nginx overwrites $remote_addr from CF-Connecting-IP ONLY for
# connections whose peer is in a Cloudflare range; a direct attacker's forged
# header is ignored and their real peer IP stands.
#
# Idempotent: validates with `nginx -t` and reloads only on change; rolls back on
# validation failure. Safe to run by hand or from cron.

set -euo pipefail

SNIPPET="${CF_SNIPPET:-/etc/nginx/snippets/cloudflare-realip.conf}"

V4="$(curl -fsS --max-time 15 https://www.cloudflare.com/ips-v4)" || { echo "[cf] failed to fetch ips-v4" >&2; exit 1; }
V6="$(curl -fsS --max-time 15 https://www.cloudflare.com/ips-v6)" || { echo "[cf] failed to fetch ips-v6" >&2; exit 1; }
[ -n "$V4" ] || { echo "[cf] empty ips-v4 — refusing to write" >&2; exit 1; }

TMP="$(mktemp)"
{
    echo "# Managed by scripts/update-cloudflare-ips.sh — do not edit by hand."
    echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Trust CF-Connecting-IP only from Cloudflare edge peers (anti-spoofing)."
    while IFS= read -r cidr; do [ -n "$cidr" ] && echo "set_real_ip_from $cidr;"; done <<< "$V4"
    while IFS= read -r cidr; do [ -n "$cidr" ] && echo "set_real_ip_from $cidr;"; done <<< "$V6"
    echo "real_ip_header CF-Connecting-IP;"
} > "$TMP"

if [ -f "$SNIPPET" ] && cmp -s "$TMP" "$SNIPPET"; then
    echo "[cf] already up to date ($(grep -c set_real_ip_from "$SNIPPET") ranges)"
    rm -f "$TMP"
    exit 0
fi

BAK="/home/micu/cloudflare-realip.$(date +%s).bak"
[ -f "$SNIPPET" ] && sudo cp "$SNIPPET" "$BAK"
sudo cp "$TMP" "$SNIPPET"
rm -f "$TMP"

if sudo nginx -t; then
    sudo systemctl reload nginx
    echo "[cf] snippet updated ($(grep -c set_real_ip_from "$SNIPPET") ranges) and nginx reloaded"
else
    echo "[cf] nginx -t failed — rolling back" >&2
    [ -f "$BAK" ] && sudo cp "$BAK" "$SNIPPET" || sudo rm -f "$SNIPPET"
    exit 1
fi
