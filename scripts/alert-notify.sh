#!/usr/bin/env bash

# Operator alert sender for the swift-vapor units.
#
# Deliberately independent of the application: it is invoked when swift-vapor
# has already failed, so it must not need the database, the app's HTTP surface,
# or any of the app's own notification machinery. Delivery reuses the Resend
# relay already proven for transactional mail and for the box's Alertmanager,
# over its HTTP API so no MTA has to be installed.
#
# Invoked two ways:
#   * systemd `OnFailure=swift-vapor-alert@%n.service` — pass `--unit NAME` and
#     the unit's own status/journal tail becomes the body.
#   * `--subject S` with the body on stdin, for scripted checks.
#
# Repeated identical alerts are throttled (see ALERT_MIN_INTERVAL_SECONDS) so a
# flapping unit cannot mailbomb the operator, but every attempt is journalled
# whether or not the mail is sent.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

API_URL="${ALERT_API_URL:-https://api.resend.com/emails}"
API_KEY_FILE="${ALERT_API_KEY_FILE:-}"
EMAIL_TO="${ALERT_EMAIL_TO:-}"
EMAIL_FROM="${ALERT_EMAIL_FROM:-}"
STATE_DIR="${ALERT_STATE_DIR:-/var/lib/swift-vapor-alerts}"
MIN_INTERVAL="${ALERT_MIN_INTERVAL_SECONDS:-3600}"
# The journal tail makes a 3am alert actionable. The app's logs are already
# privacy-minimal (coarse target kinds, /24-anonymised addresses), but this is
# still application output leaving the box — set false to send only the subject.
INCLUDE_LOGS="${ALERT_INCLUDE_LOGS:-true}"
LOG_LINES="${ALERT_LOG_LINES:-25}"
# Hard ceiling on the body regardless of the line count, so a unit that logs a
# megabyte per line cannot produce an unbounded request.
MAX_BODY_BYTES="${ALERT_MAX_BODY_BYTES:-16384}"

UNIT=""
SUBJECT=""

usage() {
    echo "usage: $0 [--unit UNIT_NAME] [--subject TEXT] [--body-file PATH]" >&2
}

BODY_FILE=""
while (( $# > 0 )); do
    case "$1" in
        --unit)      [[ $# -ge 2 ]] || { usage; exit 2; }; UNIT="$2"; shift 2 ;;
        --subject)   [[ $# -ge 2 ]] || { usage; exit 2; }; SUBJECT="$2"; shift 2 ;;
        --body-file) [[ $# -ge 2 ]] || { usage; exit 2; }; BODY_FILE="$2"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *)           usage; exit 2 ;;
    esac
done

fail() { echo "alert-notify: $*" >&2; exit 1; }

[[ -n "$EMAIL_TO" ]]   || fail "ALERT_EMAIL_TO is not configured."
[[ -n "$EMAIL_FROM" ]] || fail "ALERT_EMAIL_FROM is not configured."
[[ -n "$API_KEY_FILE" && -f "$API_KEY_FILE" ]] || fail "ALERT_API_KEY_FILE is missing: ${API_KEY_FILE:-unset}"
# Bash arithmetic evaluates its operands as expressions, so an unvalidated
# value reaching `(( ... > MAX ))` is code execution, not just a wrong number.
# These come from a root-owned unit file today; validating them keeps that from
# being the only thing standing between a config typo and a shell.
require_integer() {
    [[ "$2" =~ ^[0-9]+$ ]] || fail "$1 must be a non-negative integer."
}
require_integer ALERT_MIN_INTERVAL_SECONDS "$MIN_INTERVAL"
require_integer ALERT_LOG_LINES "$LOG_LINES"
require_integer ALERT_MAX_BODY_BYTES "$MAX_BODY_BYTES"

# A unit name reaches this from a systemd specifier; keep it to the characters
# systemd actually uses so it can never become an argument to something else.
if [[ -n "$UNIT" && ! "$UNIT" =~ ^[A-Za-z0-9@:_.\\-]+$ ]]; then
    fail "refusing to act on an implausible unit name."
fi

HOST="$(hostname -s 2>/dev/null || echo unknown)"
[[ -n "$SUBJECT" ]] || SUBJECT="${UNIT:-swift-vapor} failed on ${HOST}"

# ── Body ────────────────────────────────────────────────────────────────────
body_file="$(mktemp)"
trap 'rm -f "$body_file"' EXIT

{
    echo "Host:  $HOST"
    echo "Time:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    [[ -n "$UNIT" ]] && echo "Unit:  $UNIT"
    echo
    if [[ -n "$BODY_FILE" && -r "$BODY_FILE" ]]; then
        cat "$BODY_FILE"
    elif [[ ! -t 0 ]]; then
        cat
    fi
    if [[ -n "$UNIT" && "$INCLUDE_LOGS" == "true" ]]; then
        echo
        echo "--- systemctl status ---"
        systemctl status --no-pager --lines=0 "$UNIT" 2>&1 | head -12 || true
        echo
        echo "--- last $LOG_LINES journal lines ---"
        journalctl -u "$UNIT" --no-pager --lines="$LOG_LINES" -o short-iso 2>&1 | tail -n "$LOG_LINES" || true
    fi
} > "$body_file" 2>/dev/null || true

if (( $(stat -c '%s' "$body_file") > MAX_BODY_BYTES )); then
    truncated="$(mktemp)"
    head -c "$MAX_BODY_BYTES" "$body_file" > "$truncated"
    printf '\n\n[truncated at %s bytes]\n' "$MAX_BODY_BYTES" >> "$truncated"
    mv "$truncated" "$body_file"
fi

# Always leave a trace in the journal, even if delivery is throttled or fails —
# the journal is the record of record; the mail is only the pager.
echo "alert-notify: $SUBJECT"

# ── Throttle ────────────────────────────────────────────────────────────────
if mkdir -p "$STATE_DIR" 2>/dev/null; then
    chmod 0700 "$STATE_DIR" 2>/dev/null || true
    key="$(printf '%s' "${UNIT}|${SUBJECT}" | sha256sum | cut -c1-32)"
    marker="$STATE_DIR/$key"
    now="$(date +%s)"
    if [[ -f "$marker" ]]; then
        last="$(cat "$marker" 2>/dev/null || echo 0)"
        [[ "$last" =~ ^[0-9]+$ ]] || last=0
        if (( now - last < MIN_INTERVAL )); then
            echo "alert-notify: throttled; an identical alert was sent $(( now - last ))s ago."
            exit 0
        fi
    fi
    printf '%s' "$now" > "$marker"
fi

# ── Send ────────────────────────────────────────────────────────────────────
# python3 builds the JSON so the subject and an arbitrary log tail can never
# break out of the string they belong in. It goes to a file rather than to
# `--data "$payload"`: curl's argv is world-readable through /proc for the whole
# request, and the body carries the failed unit's journal tail.
payload_file="$(mktemp)"
trap 'rm -f "$body_file" "$payload_file"' EXIT
SUBJECT="$SUBJECT" EMAIL_TO="$EMAIL_TO" EMAIL_FROM="$EMAIL_FROM" BODY_PATH="$body_file" python3 - > "$payload_file" <<'PY'
import json, os
with open(os.environ["BODY_PATH"], "r", errors="replace") as handle:
    body = handle.read()
print(json.dumps({
    "from": os.environ["EMAIL_FROM"],
    "to": [address.strip() for address in os.environ["EMAIL_TO"].split(",") if address.strip()],
    "subject": "[swift-vapor] " + os.environ["SUBJECT"],
    "text": body,
}))
PY

# The key goes in via a header file so it never appears in argv or the journal.
header_file="$(mktemp)"
trap 'rm -f "$body_file" "$payload_file" "$header_file"' EXIT
printf 'Authorization: Bearer %s\n' "$(tr -d '\r\n' < "$API_KEY_FILE")" > "$header_file"
chmod 0600 "$header_file"

if curl --silent --show-error --fail \
        --max-time 20 --retry 2 --retry-delay 3 \
        --header @"$header_file" \
        --header 'Content-Type: application/json' \
        --data-binary @"$payload_file" \
        --output /dev/null \
        "$API_URL"; then
    echo "alert-notify: delivered to $EMAIL_TO"
else
    echo "alert-notify: DELIVERY FAILED — the alert exists only in this journal." >&2
    exit 1
fi
