# Code-level security audit — 2026-08-30

Scope: the whole repository, 22,778 lines across 186 Swift files plus the report
subprocess. Earlier audits in this directory assessed production posture and
rollout; this one reads the code. Every finding below was traced to a concrete
path, not inferred from a pattern match.

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

### F6 — Informational: admin authorization is per-handler

All five `AdminController` handlers check `isAdmin` immediately after resolving
the user, and `APIKeyRoutePolicy` denies API keys on every admin route while
failing closed on unclassified ones. Session-authenticated admin access still
rests on each handler remembering the check; a route-group middleware would make
that structural rather than conventional.

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
- **CSV formula injection.** Not applicable: exports are JSON, Markdown, HTML,
  PDF and GraphML. No CSV writer exists.
- **Privilege escalation.** No `Content`-decoded struct carries `isAdmin` or any
  role field, so no update endpoint can be coaxed into granting it.
- **Logging.** No secret, token, scan target or email address is interpolated
  into a log line; audit records store an IP prefix that is anonymised and then
  encrypted.
- **Boot gates.** Production refuses to start without a valid encryption key or
  audit signing key, and bounds notification, export and dark-web configuration
  at startup rather than trusting them at use.
