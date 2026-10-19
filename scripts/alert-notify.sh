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
# Delivery goes to Telegram when TELEGRAM_CREDENTIALS_FILE is configured (an
# env-style file with BOT_TOKEN= and CHAT_ID=), and falls back to mail only if
# Telegram cannot be reached; without it, mail as before.
#
# An alert is fingerprinted by what is wrong, not by when: the same problem is
# repeated at most once per ALERT_MIN_INTERVAL_SECONDS (a day by default), a
# different problem goes out at once, and `--resolved UNIT` (from the watched
# unit's OnSuccess=) sends one "resolved" note after an alert. A failure that
# lasted five days used to send a mail every hour of them. Every attempt is
# journalled whether or not anything is sent.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

API_URL="${ALERT_API_URL:-https://api.resend.com/emails}"
API_KEY_FILE="${ALERT_API_KEY_FILE:-}"
EMAIL_TO="${ALERT_EMAIL_TO:-}"
EMAIL_FROM="${ALERT_EMAIL_FROM:-}"
STATE_DIR="${ALERT_STATE_DIR:-/var/lib/swift-vapor-alerts}"
MIN_INTERVAL="${ALERT_MIN_INTERVAL_SECONDS:-86400}"
TELEGRAM_FILE="${TELEGRAM_CREDENTIALS_FILE:-}"
TELEGRAM_API="${TELEGRAM_API_URL:-https://api.telegram.org}"
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
RESOLVED=0

usage() {
    echo "usage: $0 [--unit UNIT_NAME | --resolved UNIT_NAME] [--subject TEXT] [--body-file PATH]" >&2
}

BODY_FILE=""
while (( $# > 0 )); do
    case "$1" in
        --unit)      [[ $# -ge 2 ]] || { usage; exit 2; }; UNIT="$2"; shift 2 ;;
        --resolved)  [[ $# -ge 2 ]] || { usage; exit 2; }; UNIT="$2"; RESOLVED=1; shift 2 ;;
        --subject)   [[ $# -ge 2 ]] || { usage; exit 2; }; SUBJECT="$2"; shift 2 ;;
        --body-file) [[ $# -ge 2 ]] || { usage; exit 2; }; BODY_FILE="$2"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *)           usage; exit 2 ;;
    esac
done

fail() { echo "alert-notify: $*" >&2; exit 1; }

HAVE_TELEGRAM=0
[[ -n "$TELEGRAM_FILE" && -r "$TELEGRAM_FILE" ]] && HAVE_TELEGRAM=1
HAVE_MAIL=0
[[ -n "$EMAIL_TO" && -n "$EMAIL_FROM" && -n "$API_KEY_FILE" && -f "$API_KEY_FILE" ]] && HAVE_MAIL=1
(( HAVE_TELEGRAM || HAVE_MAIL )) || fail "no delivery configured: neither TELEGRAM_CREDENTIALS_FILE nor ALERT_EMAIL_TO/ALERT_EMAIL_FROM/ALERT_API_KEY_FILE."
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

# ── Delivery ────────────────────────────────────────────────────────────────
# Neither the payloads nor the secrets go through argv: curl's argv is
# world-readable through /proc for the whole request. Payloads arrive on
# stdin; the Telegram URL (it carries the bot token) and the mail key through
# process substitutions, which are pipes behind /dev/fd paths, not files.
send_telegram() { # $1 = text
    local token chat
    token="$(sed -n 's/^BOT_TOKEN=//p' "$TELEGRAM_FILE" | head -1 | tr -d '\r\n"'"'"' ')"
    chat="$(sed -n 's/^CHAT_ID=//p' "$TELEGRAM_FILE" | head -1 | tr -d '\r\n"'"'"' ')"
    [[ "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ && "$chat" =~ ^-?[0-9]+$ ]] || { echo "alert-notify: Telegram credentials are malformed." >&2; return 1; }
    printf '%s' "$1" | CHAT_ID="$chat" python3 -c '
import json, os, sys
text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
if len(text) > 3900:
    text = text[:3900] + "\n\n[truncated]"
print(json.dumps({"chat_id": int(os.environ["CHAT_ID"]), "text": text, "disable_web_page_preview": True}))
' | curl --silent --show-error --fail --max-time 20 --retry 2 --retry-delay 3 \
        --config <(printf 'url = "%s/bot%s/sendMessage"\n' "$TELEGRAM_API" "$token") \
        --header 'Content-Type: application/json' --data-binary @- --output /dev/null
}

send_mail() { # $1 = subject, $2 = body
    local api_key
    api_key="$(tr -d '\r\n' < "$API_KEY_FILE")"
    [[ -n "$api_key" ]] || { echo "alert-notify: the API key file is empty." >&2; return 1; }
    printf '%s' "$2" | SUBJECT="$1" EMAIL_TO="$EMAIL_TO" EMAIL_FROM="$EMAIL_FROM" MAX_BODY_BYTES="$MAX_BODY_BYTES" python3 -c '
import json, os, sys
limit = int(os.environ["MAX_BODY_BYTES"])
raw = sys.stdin.buffer.read()
if len(raw) > limit:
    raw = raw[:limit] + ("\n\n[truncated at %d bytes]\n" % limit).encode()
print(json.dumps({
    "from": os.environ["EMAIL_FROM"],
    "to": [address.strip() for address in os.environ["EMAIL_TO"].split(",") if address.strip()],
    "subject": "[swift-vapor] " + os.environ["SUBJECT"],
    "text": raw.decode("utf-8", errors="replace"),
}))
' | curl --silent --show-error --fail --max-time 20 --retry 2 --retry-delay 3 \
        --header @<(printf 'Authorization: Bearer %s\n' "$api_key") \
        --header 'Content-Type: application/json' --data-binary @- --output /dev/null "$API_URL"
}

deliver() { # $1 = subject, $2 = body; Telegram first, mail only as its fallback
    if (( HAVE_TELEGRAM )) && send_telegram "[swift-vapor] $1"$'\n\n'"$2"; then
        echo "alert-notify: delivered to Telegram"
        return 0
    fi
    (( HAVE_TELEGRAM )) && echo "alert-notify: Telegram delivery failed; falling back to mail." >&2
    if (( HAVE_MAIL )) && send_mail "$1" "$2"; then
        echo "alert-notify: delivered to $EMAIL_TO"
        return 0
    fi
    echo "alert-notify: DELIVERY FAILED — the alert exists only in this journal." >&2
    return 1
}

# ── State ───────────────────────────────────────────────────────────────────
# A marker that cannot be written must not stop the alert: a full disk is one
# of the things this exists to report. Failing open costs a possible duplicate,
# never a silence.
state_ok=0
if mkdir -p "$STATE_DIR" 2>/dev/null; then
    chmod 0700 "$STATE_DIR" 2>/dev/null || true
    state_ok=1
else
    echo "alert-notify: could not record the throttle marker: $STATE_DIR is unusable; alerts may repeat." >&2
fi
unit_key="$(printf '%s' "${UNIT:-$SUBJECT}" | sha256sum | cut -c1-32)"
active="$STATE_DIR/active-$unit_key"

if (( RESOLVED )); then
    # Cheap on every success of a watched unit: nothing to say unless it alerted.
    [[ -f "$active" ]] || exit 0
    since="$(cut -d' ' -f1 "$active" 2>/dev/null || echo 0)"
    [[ "$since" =~ ^[0-9]+$ ]] || since=0
    took=""
    if (( since > 0 )); then took=" after $(( ($(date +%s) - since) / 60 )) minute(s)"; fi
    if deliver "RESOLVED: ${UNIT} is healthy again${took}" "Host: $HOST"$'\n'"Unit: $UNIT"; then
        rm -f -- "$active" "$STATE_DIR/$unit_key"-* 2>/dev/null || true
    fi
    exit 0
fi

# ── Body ────────────────────────────────────────────────────────────────────
# Nothing from here on writes a file except the throttle marker, and that one is
# allowed to fail. The pager has to work on the day the host is sick, and on a
# shared box /tmp is among the first things to go: when another tenant fills
# it, systemd does not refuse to start a PrivateTmp= unit — it hands it an
# empty, read-only /tmp. On 2026-09-13 that turned every alert about the
# resulting healthcheck failure into a `mktemp` crash, and nothing was sent.
# So the body lives in memory, the JSON reaches curl on stdin, and the key
# arrives through a pipe.
collect_body() {
    echo "Host:  $HOST"
    echo "Time:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if [[ -n "$UNIT" ]]; then echo "Unit:  $UNIT"; fi
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
}
# One byte past the ceiling is enough to know truncation is needed, and it
# bounds what a runaway producer can make this hold in memory.
body="$(collect_body 2>/dev/null | head -c "$(( MAX_BODY_BYTES + 1 ))" || true)"

# Always leave a trace in the journal, even if delivery is throttled or fails —
# the journal is the record of record; the message is only the pager.
echo "alert-notify: $SUBJECT"

# What is wrong, without when: the unit's own messages from the body, with
# numbers and hex runs masked, so "119h old" and "120h old", or a new process
# id, are the same problem while a different failure is a new one.
fingerprint="$(printf '%s' "$body" | python3 -c '
import hashlib, re, sys
lines = set()
for line in sys.stdin.read().splitlines():
    message = line.split("]: ", 1)[1] if "]: " in line else line
    if re.match(r"\s*(Host|Time|Unit):", message) or "systemd[" in line:
        continue
    message = re.sub(r"[0-9a-f]{8,}", "#", message.lower())
    message = re.sub(r"[0-9]+", "#", message).strip()
    if message and not message.startswith(("starting ", "finished ", "deactivated", "consumed", "triggering", "failed to start", "main process exited", "failed with result")):
        lines.add(message)
print(hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()[:32])
')"
marker="$STATE_DIR/$unit_key-$fingerprint"
now="$(date +%s)"
if (( state_ok )) && [[ -f "$marker" ]]; then
    last="$(cat "$marker" 2>/dev/null || echo 0)"
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
    if (( now - last < MIN_INTERVAL )); then
        echo "alert-notify: throttled; this same problem was reported $(( now - last ))s ago."
        exit 0
    fi
fi

repeat=""
[[ -f "$active" ]] && repeat=" (still failing)"
deliver "${SUBJECT}${repeat}" "$body" || exit 1
if (( state_ok )); then
    printf '%s' "$now" > "$marker" 2>/dev/null || echo "alert-notify: could not record the throttle marker." >&2
    # Keep when the incident started, for the resolved note's duration.
    [[ -f "$active" ]] || printf '%s\n' "$now" > "$active" 2>/dev/null || true
fi
