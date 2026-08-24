#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFLIGHT="$ROOT/scripts/production-preflight.sh"
DEPLOY="$ROOT/scripts/deploy.sh"

"$PREFLIGHT" --self-test >/dev/null
grep -qF "PREFLIGHT=\"\$SCRIPT_DIR/production-preflight.sh\"" "$DEPLOY"
grep -qF "\"\$PREFLIGHT\" --deployment-gate --repository \"\$REPOSITORY\"" "$DEPLOY"

preflight_line="$(grep -nF "\"\$PREFLIGHT\" --deployment-gate" "$DEPLOY" | cut -d: -f1)"
fetch_line="$(grep -nF "git -C \"\$REPOSITORY\" fetch" "$DEPLOY" | cut -d: -f1)"
[[ "$preflight_line" =~ ^[0-9]+$ && "$fetch_line" =~ ^[0-9]+$ ]]
(( preflight_line < fetch_line ))

if grep -Eq 'systemctl[[:space:]]+(start|stop|restart|reload|enable|disable)|git[[:space:]].*[[:space:]](fetch|merge|pull|push)' "$PREFLIGHT"; then
    echo "production preflight must remain read-only" >&2
    exit 1
fi
if grep -Eq 'printenv|/proc/[0-9]+/environ|--property(=|[[:space:]]+)Environment([[:space:]]|$)' "$PREFLIGHT"; then
    echo "production preflight must not expose runtime environment values" >&2
    exit 1
fi

echo "production preflight tests passed"
