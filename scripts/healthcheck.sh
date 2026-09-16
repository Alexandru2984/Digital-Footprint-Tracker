#!/usr/bin/env bash

# Periodic production health probe for swift-vapor.
#
# systemd's `OnFailure=` only fires when a unit reaches the *failed* state, which
# `Restart=always` reaches only on a hard crash-loop (5 starts in 10s). The
# failures that actually bite are quieter: the process is up but the database is
# gone, it restarts every few minutes without ever tripping the start limit, the
# backup timer has been silently failing for a fortnight, a certificate is about
# to expire, or the disk is filling. This probe covers those.
#
# It reports rather than repairs. Every check is independent — one failure never
# hides another — and a non-zero exit puts this unit into `failed`, which fires
# the same `swift-vapor-alert@` handler as every other unit.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SERVICE="${HEALTHCHECK_SERVICE:-swift-vapor.service}"
READY_URL="${HEALTHCHECK_READY_URL:-http://127.0.0.1:8085/ready}"
CERT_PATH="${HEALTHCHECK_CERT_PATH:-/etc/letsencrypt/live/swift.micutu.com/fullchain.pem}"
CERT_MIN_DAYS="${HEALTHCHECK_CERT_MIN_DAYS:-21}"
DISK_PATH="${HEALTHCHECK_DISK_PATH:-/srv}"
DISK_MIN_FREE_PERCENT="${HEALTHCHECK_DISK_MIN_FREE_PERCENT:-15}"
TMP_MIN_FREE_PERCENT="${HEALTHCHECK_TMP_MIN_FREE_PERCENT:-10}"
OFFSITE_STATUS="${HEALTHCHECK_OFFSITE_STATUS:-/var/lib/swift-vapor-offsite/last-success}"
OFFSITE_MAX_AGE_HOURS="${HEALTHCHECK_OFFSITE_MAX_AGE_HOURS:-36}"
BACKUP_CHECK="${HEALTHCHECK_BACKUP_CHECK:-/usr/local/libexec/swift-vapor/check-backup.sh}"
CONFIG_MANIFEST_CHECK="${HEALTHCHECK_CONFIG_MANIFEST:-/usr/local/libexec/swift-vapor/config-manifest.sh}"
# Restarts between two probe runs. One is a deploy; several is flapping that
# `Restart=always` would otherwise absorb in silence.
MAX_RESTARTS_PER_INTERVAL="${HEALTHCHECK_MAX_RESTARTS:-3}"
STATE_DIR="${HEALTHCHECK_STATE_DIR:-/var/lib/swift-vapor-alerts}"

problems=()
note() { problems+=("$1"); }

# Every threshold below lands in a `(( ... ))`, where bash evaluates its operand
# as an arithmetic *expression* — an unvalidated value there is code execution,
# not merely a wrong comparison. They come from a root-owned unit file today;
# this keeps that from being the only thing that makes it safe.
for setting in CERT_MIN_DAYS DISK_MIN_FREE_PERCENT TMP_MIN_FREE_PERCENT OFFSITE_MAX_AGE_HOURS MAX_RESTARTS_PER_INTERVAL; do
    if [[ ! "${!setting}" =~ ^[0-9]+$ ]]; then
        echo "healthcheck: $setting must be a non-negative integer." >&2
        exit 2
    fi
done

# ── 1. The unit is running ──────────────────────────────────────────────────
if ! systemctl is-active --quiet "$SERVICE"; then
    note "$SERVICE is not active (state: $(systemctl is-active "$SERVICE" 2>&1 || true))."
fi

# ── 2. Readiness, including the database ────────────────────────────────────
ready_body="$(curl --silent --show-error --max-time 10 "$READY_URL" 2>&1)" || ready_body="<request failed: $ready_body>"
# The endpoint pretty-prints its JSON, so compare with whitespace removed rather
# than against one particular spacing of the same document.
ready_compact="$(printf '%s' "$ready_body" | tr -d ' \t\n\r')"
if [[ "$ready_compact" != *'"status":"ready"'* ]]; then
    note "readiness probe did not report ready: ${ready_body:0:200}"
fi

# ── 3. Restart flapping ─────────────────────────────────────────────────────
# NRestarts is monotonic for the lifetime of the unit, so the delta between two
# probes is the restart count for that window. A reset to a lower value means
# the unit was reloaded or the counter cleared — treat it as a fresh baseline.
restarts="$(systemctl show "$SERVICE" -p NRestarts --value 2>/dev/null || echo "")"
if [[ "$restarts" =~ ^[0-9]+$ ]] && mkdir -p "$STATE_DIR" 2>/dev/null; then
    chmod 0700 "$STATE_DIR" 2>/dev/null || true
    marker="$STATE_DIR/nrestarts"
    previous="$(cat "$marker" 2>/dev/null || echo "")"
    if [[ "$previous" =~ ^[0-9]+$ ]] && (( restarts >= previous )); then
        delta=$(( restarts - previous ))
        if (( delta > MAX_RESTARTS_PER_INTERVAL )); then
            note "$SERVICE restarted $delta time(s) since the last probe (threshold $MAX_RESTARTS_PER_INTERVAL) — it is flapping without reaching the failed state."
        fi
    fi
    if ! printf '%s' "$restarts" > "$marker"; then
        note "could not record the restart counter in $STATE_DIR — flapping detection is blind until it can."
    fi
fi

# ── 4. Backup freshness ─────────────────────────────────────────────────────
# Reuses the existing read-only gate, which reports freshness without needing
# the recovery passphrase.
if [[ -x "$BACKUP_CHECK" ]]; then
    if ! backup_output="$("$BACKUP_CHECK" 2>&1)"; then
        note "backup freshness gate failed: ${backup_output:0:300}"
    fi
else
    note "backup freshness gate is missing or not executable at $BACKUP_CHECK."
fi

# ── 5. Certificate expiry ───────────────────────────────────────────────────
if [[ -r "$CERT_PATH" ]]; then
    if expires_at="$(openssl x509 -enddate -noout -in "$CERT_PATH" 2>/dev/null | cut -d= -f2)"; then
        if expires_epoch="$(date -d "$expires_at" +%s 2>/dev/null)"; then
            days_left=$(( (expires_epoch - $(date +%s)) / 86400 ))
            if (( days_left < CERT_MIN_DAYS )); then
                note "TLS certificate expires in ${days_left} day(s) (threshold ${CERT_MIN_DAYS}): $CERT_PATH"
            fi
        else
            note "could not parse the certificate expiry date: $expires_at"
        fi
    else
        note "could not read the certificate expiry from $CERT_PATH."
    fi
else
    note "TLS certificate is unreadable at $CERT_PATH."
fi

# ── 6. Disk headroom ────────────────────────────────────────────────────────
if used_percent="$(df --output=pcent "$DISK_PATH" 2>/dev/null | tail -1 | tr -dc '0-9')" && [[ -n "$used_percent" ]]; then
    free_percent=$(( 100 - used_percent ))
    if (( free_percent < DISK_MIN_FREE_PERCENT )); then
        note "only ${free_percent}% free on the filesystem holding $DISK_PATH (threshold ${DISK_MIN_FREE_PERCENT}%)."
    fi
else
    note "could not read disk usage for $DISK_PATH."
fi

# ── 7. Shared scratch space ─────────────────────────────────────────────────
# /tmp in this unit is private, but it is carved out of the host's shared tmpfs,
# so its headroom is the host's. When another tenant fills it, systemd does not
# fail PrivateTmp= units — it quietly hands them an empty, read-only /tmp — and
# anything needing scratch space breaks without saying why. On 2026-09-13 an
# unrelated R service filled it, and this probe reported the fallout as
# configuration drift. Two signals: this unit cannot write /tmp at all
# (degraded now), or headroom is low (degraded soon). Only the write catches the
# first — in a degraded unit, df describes the substitute mount, not the full one.
if scratch="$(mktemp /tmp/swift-vapor-healthcheck.XXXXXX 2>&1)"; then
    rm -f -- "$scratch"
    for metric in pcent ipcent; do
        if used="$(df --output="$metric" /tmp 2>/dev/null | tail -1 | tr -dc '0-9')" && [[ -n "$used" ]]; then
            free=$(( 100 - used ))
            if (( free < TMP_MIN_FREE_PERCENT )); then
                if [[ "$metric" == ipcent ]]; then what="inodes"; else what="space"; fi
                note "only ${free}% of /tmp ${what} free on this host (threshold ${TMP_MIN_FREE_PERCENT}%) — when the shared /tmp fills, every PrivateTmp= unit here gets a read-only /tmp."
            fi
        else
            note "could not read /tmp usage ($metric)."
        fi
    done
else
    note "/tmp is not writable here (${scratch:0:160}) — the host's shared /tmp is full or read-only, so systemd has given every PrivateTmp= unit on this host a read-only /tmp; backups need it. Find what filled it."
fi

# ── 8. Off-host copy freshness ──────────────────────────────────────────────
# A local backup survives a bad migration; it does not survive the host. The
# copy is written by swift-vapor-offsite.service only after it re-reads the
# far side and the checksums match, so this timestamp means "verified there",
# not "upload returned". Set HEALTHCHECK_OFFSITE_STATUS= (empty) to opt out on a
# host with no off-host destination — a check that quietly stops running is
# indistinguishable from one that finds nothing.
if [[ -n "$OFFSITE_STATUS" ]]; then
    if [[ -f "$OFFSITE_STATUS" ]]; then
        if copied_at="$(stat -c '%Y' "$OFFSITE_STATUS" 2>/dev/null)" && [[ "$copied_at" =~ ^[0-9]+$ ]]; then
            age_hours=$(( ( $(date +%s) - copied_at ) / 3600 ))
            if (( age_hours > OFFSITE_MAX_AGE_HOURS )); then
                note "the off-host backup copy is ${age_hours}h old (threshold ${OFFSITE_MAX_AGE_HOURS}h) — the backups exist only on this host."
            fi
        else
            note "could not read the off-host copy timestamp at $OFFSITE_STATUS."
        fi
    else
        note "no off-host backup copy has ever been verified ($OFFSITE_STATUS is missing) — the backups exist only on this host."
    fi
fi

# ── 9. Host configuration drift ─────────────────────────────────────────────
# Catches an out-of-band edit to a unit, vhost, CSP snippet, environment file or
# installed helper. Not an availability problem — the service keeps running —
# but a change nobody recorded is how a live config silently stops matching the
# repository it is supposed to mirror.
# Set HEALTHCHECK_CONFIG_MANIFEST= (empty) to opt out deliberately. A missing
# helper at a configured path is reported rather than skipped: a drift check
# that quietly stops running is indistinguishable from one that finds nothing.
if [[ -n "$CONFIG_MANIFEST_CHECK" ]]; then
    if [[ -x "$CONFIG_MANIFEST_CHECK" ]]; then
        if ! drift_output="$("$CONFIG_MANIFEST_CHECK" --verify 2>&1)"; then
            note "host configuration drift: ${drift_output:0:400}"
        fi
    else
        note "configuration drift gate is missing or not executable at $CONFIG_MANIFEST_CHECK."
    fi
fi

# ── Report ──────────────────────────────────────────────────────────────────
if (( ${#problems[@]} == 0 )); then
    echo "healthcheck: all checks passed."
    exit 0
fi

echo "healthcheck: ${#problems[@]} problem(s) found." >&2
for problem in "${problems[@]}"; do
    echo "  - $problem" >&2
done
exit 1
