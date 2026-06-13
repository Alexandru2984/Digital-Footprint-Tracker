#!/usr/bin/env bash
#
# Regenerates the nginx CSP `script-src` SHA-256 hashes for swift.micutu.com from
# the inline <script> blocks of the served HTML pages, validates the config, and
# reloads nginx. Idempotent: a no-op when nothing changed.
#
# Why this exists: the SPA's logic lives in an inline <script>, pinned by hash in
# the CSP. Any edit to that script changes its hash, so the CSP must be updated in
# lockstep or the browser blocks the script and the whole app breaks. This makes
# that lockstep automatic (run by deploy.sh; safe to run by hand).
#
# Safe by construction: backs up the vhost, validates with `nginx -t`, and rolls
# back if validation fails. The vhost is world-readable, so the rewrite happens in
# a temp file as the invoking user and only the final `cp` needs sudo.

set -euo pipefail

VHOST="${SWIFT_VHOST:-/etc/nginx/sites-enabled/swift.micutu.com}"
FRONTEND="${SWIFT_FRONTEND:-/home/micu/swift+vapor/frontend}"

[ -f "$VHOST" ]    || { echo "[csp] vhost not found: $VHOST" >&2; exit 1; }
[ -d "$FRONTEND" ] || { echo "[csp] frontend not found: $FRONTEND" >&2; exit 1; }

# Emit one quoted 'sha256-…' token per inline <script> (no src=) in a file.
hash_file() {
    node -e '
        const fs = require("fs"), cp = require("child_process");
        const html = fs.readFileSync(process.argv[1], "utf8");
        const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g;
        let m;
        while ((m = re.exec(html))) {
            const b = cp.execSync("openssl dgst -sha256 -binary | openssl base64 -A", { input: m[1] }).toString();
            process.stdout.write("'\''sha256-" + b + "'\'' ");
        }
    ' "$1"
}

TOKENS=""
for page in index.html login.html register.html admin.html; do
    [ -f "$FRONTEND/$page" ] && TOKENS+="$(hash_file "$FRONTEND/$page")"
done
TOKENS="$(printf '%s' "$TOKENS" | tr -s ' ' | sed 's/[[:space:]]*$//')"
[ -n "$TOKENS" ] || { echo "[csp] no inline scripts found — nothing to pin" >&2; exit 1; }
echo "[csp] script-src hashes: $TOKENS"

# Rewrite the contiguous run of 'sha256-…' tokens (only script-src has them).
TMP="$(mktemp)"
NEW="$TOKENS" perl -0777 -pe \
    "s{'sha256-[A-Za-z0-9+/=]+'(?:\\s+'sha256-[A-Za-z0-9+/=]+')*}{\$ENV{NEW}}" \
    "$VHOST" > "$TMP"

FIRST="$(printf '%s' "$TOKENS" | awk '{print $1}')"
grep -qF "$FIRST" "$TMP" || { echo "[csp] rewrite did not apply — aborting" >&2; rm -f "$TMP"; exit 1; }

if cmp -s "$TMP" "$VHOST"; then
    echo "[csp] already up to date — no reload needed"
    rm -f "$TMP"
    exit 0
fi

BAK="/home/micu/swift.micutu.com.vhost.$(date +%s).bak"
sudo cp "$VHOST" "$BAK"
sudo cp "$TMP" "$VHOST"
rm -f "$TMP"

if sudo nginx -t; then
    sudo systemctl reload nginx
    echo "[csp] nginx reloaded with updated hashes (backup: $BAK)"
else
    echo "[csp] nginx -t failed — restoring backup" >&2
    sudo cp "$BAK" "$VHOST"
    exit 1
fi
