#!/usr/bin/env bash

set -euo pipefail

# The pager has to work on the day the host is sick. On 2026-09-13 another
# tenant filled the shared /tmp, systemd handed every PrivateTmp= unit a
# read-only /tmp instead, and each alert about the resulting healthcheck failure
# died on its first mktemp — nothing was sent. So every case here runs the real
# sender with TMPDIR pointing at a directory that does not exist, against a
# local stand-in for the mail API.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SENDER="$ROOT/scripts/alert-notify.sh"
TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
    rm -rf -- "$TMP"
}
trap cleanup EXIT

fail() { echo "alert-notify contract: $1" >&2; exit 1; }

# Static half. bash can fall back from an unusable TMPDIR to /tmp for a
# here-document, so the dynamic cases below cannot see one; this can.
if grep -nE '^[^#]*(\bmktemp\b|<<)' "$SENDER"; then
    fail "the sender must not create temp files (mktemp, here-documents or here-strings)"
fi

# Records each request and answers with whatever status the test last set.
CAPTURE="$TMP/capture"
mkdir -p "$CAPTURE"
printf '200' > "$TMP/status"
python3 - "$CAPTURE" "$TMP/status" "$TMP/port" <<'PY' &
import http.server, json, os, sys
capture, status_file, port_file = sys.argv[1:4]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        name = os.path.join(capture, "%03d.json" % len(os.listdir(capture)))
        with open(name, "w") as handle:
            json.dump({
                "authorization": self.headers.get("Authorization"),
                "content_type": self.headers.get("Content-Type"),
                "body": body.decode(),
            }, handle)
        with open(status_file) as handle:
            self.send_response(int(handle.read()))
        self.end_headers()

    def log_message(self, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file + ".partial", "w") as handle:
    handle.write(str(server.server_port))
os.rename(port_file + ".partial", port_file)
server.serve_forever()
PY
SERVER_PID=$!
for _ in $(seq 50); do [[ -s "$TMP/port" ]] && break; sleep 0.1; done
[[ -s "$TMP/port" ]] || fail "the capture server did not start"
PORT="$(cat "$TMP/port")"

KEY_FILE="$TMP/api-key"
printf 'fixture-%s\n' "not-a-real-key" > "$KEY_FILE"
chmod 0600 "$KEY_FILE"

send() {
    env -i PATH="$PATH" HOME="$TMP" \
        TMPDIR="$TMP/no-scratch-space" \
        ALERT_API_URL="http://127.0.0.1:$PORT/emails" \
        ALERT_API_KEY_FILE="$KEY_FILE" \
        ALERT_EMAIL_TO="ops@example.test, second@example.test" \
        ALERT_EMAIL_FROM="alerts@example.test" \
        ALERT_STATE_DIR="$TMP/state" \
        ALERT_MAX_BODY_BYTES="${MAX_BYTES:-16384}" \
        "$SENDER" "$@"
}
requests() { find "$CAPTURE" -name '*.json' | wc -l; }
last_request() { find "$CAPTURE" -name '*.json' | sort | tail -1; }

# 1. Delivery with no usable scratch space, and the request is exactly right.
out="$(printf 'disk is at 99%%\n' | send --subject "disk full")" \
    || fail "expected delivery with no writable scratch space"
grep -q "delivered to" <<<"$out" || fail "expected a delivery confirmation"
python3 - "$(last_request)" "$KEY_FILE" <<'PY'
import json, sys
request = json.load(open(sys.argv[1]))
key = open(sys.argv[2]).read().strip()
assert request["authorization"] == "Bearer " + key, request["authorization"]
assert request["content_type"] == "application/json", request["content_type"]
payload = json.loads(request["body"])
assert payload["subject"] == "[swift-vapor] disk full", payload["subject"]
assert payload["to"] == ["ops@example.test", "second@example.test"], payload["to"]
assert payload["from"] == "alerts@example.test", payload["from"]
assert "disk is at 99%" in payload["text"], payload["text"]
PY

# 2. An identical alert inside the interval is journalled but not sent.
before="$(requests)"
out="$(send --subject "disk full" </dev/null)" || fail "a throttled alert must still exit 0"
grep -q "throttled" <<<"$out" || fail "expected the repeat to be throttled"
[[ "$(requests)" == "$before" ]] || fail "a throttled alert must not reach the API"

# 3. The body ceiling holds, and says so.
head -c 5000 /dev/zero | tr '\0' 'x' | MAX_BYTES=200 send --subject "noisy unit" >/dev/null \
    || fail "expected an oversized body to be truncated, not refused"
python3 - "$(last_request)" <<'PY'
import json, sys
text = json.loads(json.load(open(sys.argv[1]))["body"])["text"]
marker = "\n\n[truncated at 200 bytes]\n"
assert text.endswith(marker), text[-60:]
assert len(text.encode()) == 200 + len(marker), len(text.encode())
PY

# 4. A throttle marker that cannot be written must not stop the mail — a full
#    disk is one of the things this exists to report. A directory squatting on
#    the marker's path makes the write fail without needing root.
key="$(printf '%s' "|marker unwritable" | sha256sum | cut -c1-32)"
mkdir -p "$TMP/state/$key"
before="$(requests)"
err="$(send --subject "marker unwritable" </dev/null 2>&1 >/dev/null)" \
    || fail "expected delivery even when the throttle marker cannot be written"
grep -q "sending anyway" <<<"$err" || fail "expected the marker failure to be journalled"
(( $(requests) == before + 1 )) || fail "expected exactly one request despite the marker failure"

# 5. A rejected request is a failure, loudly.
printf '400' > "$TMP/status"
if send --subject "rejected" </dev/null >/dev/null 2>"$TMP/rejected.err"; then
    fail "expected a rejected request to fail"
fi
grep -q "DELIVERY FAILED" "$TMP/rejected.err" || fail "expected the failure to be journalled"

echo "alert-notify contract tests passed"
