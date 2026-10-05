#!/usr/bin/env bash

set -euo pipefail

# An exception list is only safe while it stays honest: it must waive exactly
# what it names, refuse everything else, and go stale loudly rather than
# quietly. Driven with fixture reports, so it tests the rules and not today's
# dependency tree.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AUDIT="$ROOT/scripts/audit-frontend.mjs"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

fail() { echo "audit-frontend contract: $1" >&2; exit 1; }

report() {  # $1 = advisory id, $2 = severity
    cat > "$TMP/report.json" <<JSON
{"auditReportVersion":2,
 "vulnerabilities":{
   "braces":{"name":"braces","severity":"$2","via":[
     {"source":1240992,"name":"braces","severity":"$2","url":"https://github.com/advisories/$1"}]},
   "micromatch":{"name":"micromatch","severity":"$2","via":["braces"]}},
 "metadata":{"vulnerabilities":{"high":2,"critical":0,"total":2}}}
JSON
}
allowlist() { printf '[{"id":"%s","until":"%s","reason":"fixture"}]\n' "$1" "$2" > "$TMP/allow.json"; }
run() { node "$AUDIT" --input "$TMP/report.json" --allowlist "$TMP/allow.json"; }

# 1. Named, in date: accepted, and the reason is printed so it stays visible.
report "GHSA-vfj7-8cjw-p6xm" high
allowlist "GHSA-vfj7-8cjw-p6xm" "2099-01-01"
out="$(AUDIT_TODAY=2026-10-05 run)" || fail "expected a listed advisory to pass"
grep -q "accepted until 2099-01-01" <<<"$out" || fail "expected the acceptance to be reported"

# 2. A different advisory is not covered by the exception.
report "GHSA-0000-0000-0000" high
if err="$(AUDIT_TODAY=2026-10-05 run 2>&1)"; then fail "expected an unlisted advisory to fail"; fi
grep -q "GHSA-0000-0000-0000" <<<"$err" || fail "expected the unlisted advisory to be named"
grep -q "is not in" <<<"$err" || fail "expected guidance on what to do"

# 3. An expired exception stops waiving.
report "GHSA-vfj7-8cjw-p6xm" high
allowlist "GHSA-vfj7-8cjw-p6xm" "2026-10-01"
if err="$(AUDIT_TODAY=2026-10-05 run 2>&1)"; then fail "expected an expired exception to fail"; fi
grep -q "that date has passed" <<<"$err" || fail "expected the expiry to be explained"

# 4. An exception for something no longer reported must be removed, not kept.
cat > "$TMP/report.json" <<'JSON'
{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"high":0,"critical":0,"total":0}}}
JSON
allowlist "GHSA-vfj7-8cjw-p6xm" "2099-01-01"
if err="$(AUDIT_TODAY=2026-10-05 run 2>&1)"; then fail "expected a stale exception to fail"; fi
grep -q "no longer reported" <<<"$err" || fail "expected the stale exception to be named"

# 5. A clean report with an empty allowlist passes.
printf '[]\n' > "$TMP/allow.json"
AUDIT_TODAY=2026-10-05 run >/dev/null || fail "expected a clean report to pass"

# 6. Moderate findings are not the gate's business — it matches npm's high level.
report "GHSA-1111-1111-1111" moderate
printf '[]\n' > "$TMP/allow.json"
AUDIT_TODAY=2026-10-05 run >/dev/null || fail "expected a moderate advisory to be out of scope"

echo "audit-frontend contract tests passed"
