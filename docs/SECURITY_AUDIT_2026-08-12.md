# Extreme security audit — 2026-08-12

## Post-audit production update — 2026-08-12 12:12 UTC

Two edge incidents from the snapshot below were mitigated without deploying the
pending backend/systemd/immutable-release cutover:

- Commit `13ef89c` added a 128-bit nginx `$request_id` nonce to `script-src`
  while retaining exact hashes and forbidding JavaScript `unsafe-inline`. The
  root-owned installer updated the live CSP with backup, successful `nginx -t`
  and graceful reload.
- Two independent Cloudflare responses had different CSP nonces. In each
  response Cloudflare propagated the matching nonce to the outer and nested
  JavaScript Detections scripts; all four current application hashes were
  present and `cf-cache-status` was `DYNAMIC`.
- The already-versioned Cloudflare peer guard was enabled only for the live
  `swift.micutu.com` TLS vhost. Direct IPv4 and a direct request with a forged
  `CF-Connecting-IP` now return 403; Cloudflare, `/health` and onion probes
  return 200.
- The host has no browser runtime, so actual browser execution and console
  validation remain an acceptance gate. The Swift vhost has no matching direct
  IPv6 TLS listener (the address presents another vhost's certificate), so the
  site is not directly reachable there; explicit IPv6 closure and Cloudflare
  Authenticated Origin Pulls remain open.
- Cloudflare dashboard policy was not changed or inspected. Confirm that the
  active bot/WAF product consumes the JSD outcome; JSD signal collection alone
  is not an enforcement action.

Rollback copies are retained under `/var/lib/swift-vapor-csp-backups/` and
`/var/lib/swift-vapor-nginx-backups/`. The audit's overall **NO-GO** remains in
force because backup recovery, runtime identity, broad host authority and the
immutable release cutover are still open.

## Executive verdict

**NO-GO for an unattended production rollout.** The repository is materially
safer and all changes in this pass are committed locally, but production is in
a split state: nginx serves mutable frontend files directly from the checkout,
the running backend predates this pass, and the installed `/etc` configuration
does not match the hardened repository configuration.

There are four immediate production blockers:

1. **No current recoverable backup:** the daily job failed on 2026-08-09 through
   2026-08-12 because its encrypted passphrase credential is absent. The newest
   local dump is an unencrypted `2026-07-20` gzip and no isolated restore result
   was demonstrated.
2. **Host-wide identity blast radius:** the web service runs as the personal
   `micu` account, which currently has `NOPASSWD: ALL`. Live
   `NoNewPrivileges=true` blocks a direct setuid/sudo hop from inside the unit,
   but the service still shares readable identity state and secrets with a
   root-equivalent interactive/deploy account. A sandbox escape or stolen
   unrestricted automation key completes the root path.
3. **The live SPA is currently CSP-blocked:** nginx serves the modified checkout,
   but the installed CSP lacks both hashes required by `frontend/index.html`.
   Login and registration hashes still match; the two main application scripts
   do not. This is direct evidence that checkout-based deployment is unsafe.
4. **Edge controls are not active at the origin:** the installed clearnet vhost
   trusts Cloudflare real-IP headers from known peers but does not contain the
   repository's Cloudflare-only origin guard. Direct-origin bypass therefore
   remains possible unless an unverified external firewall control blocks it.

The correct next action is the controlled rollout in
`docs/PRODUCTION_ROLLOUT.md`, beginning with a new encrypted backup and an
isolated restore. Do not mark a repository remediation as deployed merely
because its commit exists.

## Snapshot and scope

Evidence was collected read-only at `2026-08-12T02:55:00Z`. Secret values were
not printed. This was a source/configuration audit plus non-invasive production
inspection, not a destructive penetration test.

Reviewed surfaces:

- Swift/Vapor routes, authentication, authorization, encryption, migrations,
  scan execution, plugins, HTTP egress, subprocesses, reports and exports;
- browser HTML/JavaScript/CSS, CSP/SRI behavior and responsive layouts;
- PostgreSQL data lifecycle, backup, recovery assumptions and observability;
- nginx clearnet/onion ingress, Cloudflare proxy trust and direct-origin policy;
- systemd confinement, Unix/SSH/sudo identities and co-resident host exposure;
- GitHub Actions, SwiftPM, npm, Python/container/deployment supply chain;
- the current live process, listeners, timers, configuration drift and file modes.

Not performed:

- credential guessing, exploit payloads, traffic floods or destructive DB tests;
- email/webhook/API calls to third parties;
- production restart, migration, nginx reload, Cloudflare/firewall change,
  secret rotation, Git push or `/etc` installation;
- browser automation: no browser runtime was installed on this production host;
- intrusive review of unrelated applications sharing the VPS.

## Production evidence

| Control | Observed live state | Repository target |
|---|---|---|
| Backend | Active, PID `2535950`, zero restarts, binary built 2026-08-09 | Current pass is not built/deployed |
| Runtime identity | `User=micu`, `Group=micu`, personal checkout | Non-login `swift-vapor`, immutable `/srv/swift-vapor/current` |
| systemd exposure | `5.2 MEDIUM` | Offline target `2.8 OK` |
| sudo | `micu` has `(ALL) NOPASSWD: ALL` | Three enumerated deploy operations only |
| Backup timer | Active, job failed, status 1 | Encrypted credential, verified marker and critical alert |
| Latest dump | Seven local plaintext `.sql.gz`; newest 2026-07-20 | Encrypted verified dump, immutable offsite copy, restore proof |
| nginx document root | `/home/micu/swift+vapor/frontend` | `/srv/swift-vapor/current/frontend` |
| Main SPA CSP | Two required hashes missing | Release-aware old+new transition, then exact new policy |
| Origin guard | Not present in installed public vhost | Cloudflare-peer guard plus Authenticated Origin Pulls |
| App listener | `127.0.0.1:8085` | Retain loopback-only listener |
| nginx syntax | `sudo nginx -t` succeeds | Validate before every atomic reload |
| Native toolchain | Swift 6.1; CI/project target 6.2 | Align host or deploy a verified artifact/container |
| PDF/holehe runtime | `reportlab` unavailable; `holehe --help` exits 1 | Hash-locked Python runtime under service identity |
| Frontend audit | npm reports 0 known vulnerabilities | Retain CI audit and integrity gate |

Five of six authorized SSH keys are unrestricted; the one named
`swift-vapor-deploy@github-actions` alone has both a forced command and
`restrict`. Public-key material is not secret, but unrestricted automation keys
are privileged credentials and must be inventoried before revocation.

## Assets, actors and trust boundaries

### Highest-value assets

- scan targets, raw findings, entity graphs, timelines, breach history and reports;
- account email/username, password hashes, sessions, TOTP material and API keys;
- provider, SMTP, metrics, database and data-encryption credentials;
- share capabilities, webhook URLs/tokens and notification destinations;
- PostgreSQL integrity, encryption-key continuity, backups and audit evidence;
- deploy keys, release artifacts, nginx/systemd policy and host root access;
- availability and provider quotas of this and other services on the shared VPS.

### Trust boundaries

```text
Internet browser -> Cloudflare -> nginx -> Vapor -> PostgreSQL
Tor client ---------------------> onion nginx -> Vapor
Vapor -> DNS / external APIs / arbitrary target-controlled hosts
Vapor -> whois, holehe and PDF child processes
GitHub Actions -> forced SSH command -> deploy helper -> systemd/nginx
PostgreSQL -> pg_dump -> gzip -> GPG -> local/offsite backup
Prometheus -> token-protected /metrics -> alert delivery
Shared URL holder -> opaque share capability -> selected report
```

Every value returned by an OSINT provider, DNS server, target host, uploaded
investigation or share visitor is attacker-controlled even when the upstream
brand is trusted.

## STRIDE threat model

| Category | Credible scenario | Current controls | Residual action |
|---|---|---|---|
| Spoofing | Forge client IP, steal session/API/share capability, impersonate CI | Loopback-only proxy-header trust, scoped API keys, rotated sessions, share hashes/expiry | Deploy edge configs; passkeys; device/session inventory; constrain all automation keys |
| Tampering | Modify results/audit rows, transplant encrypted DB values, inject frontend/release files | AES-GCM, output escaping, read-only release manifests prepared | Add AAD row/field binding, append-only remote audit, signed artifacts and deploy verification |
| Repudiation | User/operator denies a scan/export; attacker edits co-resident logs | Application audit rows and anonymized IP prefixes | Separate security event stream, tamper-evident hash chain, remote immutable retention |
| Information disclosure | Cache OSINT APIs, leak tokens in URLs/logs, XSS via provider data, read plaintext backup | No-store, POST share unlock, inert reports, escaping, encrypted backup code | Deploy fixes; split secrets; encrypt legacy backups; eliminate anonymous scan-ID capability reuse |
| Denial of service | Fan-out scans, SSE DB polling, slow DNS, subprocess descendants, huge exports | Per-process gates, rate/body/output/time limits | Durable queue/leases, cursor SSE, DNS resolver deadlines, process groups/cgroups, paged exports |
| Elevation of privilege | App RCE reads same-UID personal state; stolen unrestricted SSH key or sandbox escape reaches a passwordless-root account | `NoNewPrivileges` plus partial live sandbox | Install dedicated runtime identity and narrow sudo; segment the shared host |

## Findings register

Status meanings:

- **Fixed in repo** — committed and tested, but not necessarily active live.
- **Prepared** — operational configuration/runbook exists but requires installation.
- **Open** — implementation or operator evidence is still missing.
- **Live incident** — presently affects production behavior or recoverability.

### P0 — critical / immediate

| ID | Finding and impact | Status | Required gate |
|---|---|---|---|
| P0-01 | Daily backup has failed at least 2026-08-09..12; only seven local plaintext dumps dated 2026-07-14..20 remain. Host/disk compromise or DB corruption can cause unrecoverable loss. | Live incident; monitoring code prepared | Provision systemd encrypted credential, install unit, create encrypted dump, copy off-host, isolated restore, record RPO/RTO |
| P0-02 | Web runtime and deploy/personal user are `micu`, which has passwordless unrestricted root outside the service sandbox. Same-UID disclosure plus a sandbox/SSH boundary failure has host-wide blast radius. | Runtime split prepared; live open | Install non-login `swift-vapor`, move runtime to `/srv`, replace broad sudo, rotate affected credentials |
| P0-03 | Main SPA scripts were blocked by CSP drift while nginx served mutable checkout content. | Live edge mitigation applied; immutable release/browser gate open | Verify a real browser, then move nginx to the immutable release immediately |
| P0-04 | Running backend and `/etc` configs predate the security commits while frontend files already changed. Security posture is mixed and rollback state is ambiguous. | Prepared | Execute and record the controlled rollout; production SHA/config checksums must match accepted release |

### P1 — high

| ID | Finding and impact | Status | Required action |
|---|---|---|---|
| P1-01 | Direct origin access could bypass Cloudflare WAF/bot/rate policies. | IPv4 vhost guard deployed; AOP/IPv6 closure open | Add AOP/mTLS, cover every served address and continuously probe for bypass |
| P1-02 | Five authorized SSH keys are unrestricted, including two automation-labelled keys. Theft provides an interactive `micu` shell and currently passwordless root. | Open | Identify owners out-of-band, replace per project with forced commands + `restrict`, revoke old keys |
| P1-03 | Database, SMTP, vendors and encryption key share one flat process environment. RCE exposes all capabilities; key and data reside together. | Open | Split web/worker credentials, systemd credentials or secret manager, rotate after identity boundary is fixed |
| P1-04 | One raw 256-bit key is used directly for AES-GCM and HMAC blind indexes, without HKDF domain separation, AAD row/table/field binding or an online key generation/rotation scheme. A DB writer can transplant valid ciphertext between compatible fields. | Open | Versioned envelope, HKDF subkeys, AAD, KEK/DEK registry, resumable rotation and rollback checkpoints |
| P1-05 | Scan admission, schedules and watches are process-local tasks. Queue entries have no wait deadline/lease; crash/restart can strand or duplicate work and replicas multiply limits. | Open | Durable Postgres/Redis queue, leases, idempotency, leader election, retry/DLQ, dedicated workers |
| P1-06 | Subprocess timeout signals only the immediate PID; descendants can retain pipes. DNS validation runs in detached blocking work without a resolver deadline. | Open | New process group/cgroup, kill whole tree, bounded resolver pool/deadline and cancellation tests |
| P1-07 | SSE reloads and decrypts every result each second without stable ordering, then uses `dropFirst(count)`. Concurrent inserts can duplicate/miss events and amplify DB/CPU load. | Open | Monotonic result cursor, ordered indexed query, bounded batch, resumable `Last-Event-ID` |
| P1-08 | Correlation, reports, account export and several graph paths materialize all scans/results. Account export caps audit rows at 1,000 while describing an all-data export. Large accounts can exhaust memory and receive incomplete access data. | Open | Streaming/paged jobs, size quotas, asynchronous encrypted export, explicit completeness manifest |
| P1-09 | Security/audit evidence is mutable and co-resident; no central alert path was verified. A compromised app/DB can erase both act and evidence. | Open | Append-only writer role, remote signed export/SIEM, alert routing and retention controls |
| P1-10 | Host PDF and holehe dependencies are broken. Report generation and one plugin can fail despite a healthy HTTP process. | Prepared in container/runtime lock; live open | Install tested runtime under exact service sandbox and add authenticated report/plugin smoke gates |

### P2 — medium

| ID | Finding and impact | Status | Required action |
|---|---|---|---|
| P2-01 | Notification metrics count attempts as sent even when configuration is absent or delivery fails; email is attempted regardless of a channel preference. Operators receive false success signals. | Open | Typed delivery result, attempt/success/failure counters, channel policy and retry/DLQ |
| P2-02 | `/health` is public and performs a DB count query. It is rate-limited but still couples liveness and database readiness. | Open | Constant-cost liveness; authenticated/loopback readiness with `SELECT 1` and dependency status |
| P2-03 | Corrupt tagged ciphertext triggers `preconditionFailure`, converting a bad/attacker-modified DB row into process termination. | Open | Throw typed errors, quarantine row, security event and fail only the request/job |
| P2-04 | Email and username remain plaintext in the user table while other sensitive fields are encrypted. | Open | Data-class decision; normalized blind indexes plus encryption if operational requirements allow |
| P2-05 | Crypto migrations load whole tables and are not chunked/checkpointed. A large production dataset can cause long locks, memory pressure or hard-to-resume partial work. | Open | Batched idempotent migration with cursor, metrics, dry-run and verification |
| P2-06 | Anonymous scans remain bearer capabilities by UUID and completed dedup returns the same capability. Referrer/history/browser compromise can expose results for the reuse window. | Open | Short-lived separate read token or require account; rotate capability on reuse |
| P2-07 | Outbound HTTP creates and shuts down a client per request; `hostPreChecked` is unused. This wastes connection pools and complicates cancellation/telemetry. | Open | Shared policy-aware client/pool with per-request DNS pin and metrics |
| P2-08 | Swift 6.1 host differs from CI 6.2; mutable `Sendable`, deprecated async APIs and unreachable catches produce extensive warnings that become Swift 6 errors. | Open | Align toolchain, warning budget, strict-concurrency migration by module |
| P2-09 | Swift advisory coverage is manual. OSV Scanner does not natively consume SwiftPM lockfiles; CI lacks a complete secret/SAST/SBOM/signature gate. | Partial | GitHub advisory/Dependabot, gitleaks, Semgrep, SBOM, artifact signing and deploy verification |
| P2-10 | `style-src 'unsafe-inline'` remains and large inline scripts make CSP operationally fragile. | Partial | External hashed assets, static strict CSP, report collection, Trusted Types evaluation |
| P2-11 | Multiple unrelated public services share the host. Same-kernel or same-user compromise increases lateral-movement and availability blast radius. | Outside repo / open | Owner inventory, private binding/VPN, separate identities/containers or separate hosts |
| P2-12 | Backups are single-host and lack PITR, immutable offsite retention and recurring restore drills. | Open | Encrypted WAL archive, daily/weekly/monthly tiers, object lock, quarterly game day |

### P3 — low / governance and defense in depth

| ID | Finding | Action |
|---|---|---|
| P3-01 | No formal target authorization/acceptable-use record for an OSINT platform | Purpose/consent confirmation, prohibited targets, abuse/takedown queue and operator review |
| P3-02 | Provider licenses, subprocessors, target-data disclosure and retention are not represented as an enforceable registry | Vendor inventory with owner, data classes, region, terms, DPA, expiry and kill switch |
| P3-03 | No generated route-to-authorization matrix | CI-enforced route classification and property-based cross-tenant IDOR tests |
| P3-04 | Cloudflare CIDR refresh, certificate expiry and config drift are not centrally monitored | Read-only drift probes, expiry alerts and reviewed atomic refresh timer |
| P3-05 | No real-browser visual/accessibility regression suite | Playwright in disposable CI for 320/375/768/1440 widths, keyboard, WCAG and CSP console assertions |

## Repository remediations in this pass

All commits use the repository's configured author only. There are no AI,
contributor or co-author trailers.

| Commit | Remediation |
|---|---|
| `5cb455c` | Refreshed vulnerable frontend build dependencies |
| `08a6f08` | Applied `no-store` to every API/error response |
| `fb7026b` | Trusted forwarding headers only from loopback nginx peers |
| `eb12be9` | Rejected non-global IPv4/IPv6 SSRF destinations and pinned DNS |
| `666d28c` | Bounded plugin results by UTF-8 byte size |
| `a849f1d` | Required password and valid TOTP to disable 2FA |
| `abe5b18` | Escaped imported investigation attributes |
| `37ed1eb` | Removed share passwords/tokens from request URLs |
| `852b6eb` | Offloaded expensive share password hashing from event loops |
| `fefa3a5` | Honored explicit disabled scan retention |
| `3f6517d` | Enforced bootstrap administrator credential policy |
| `d86a2b5` | Updated `swift-nio-http2` beyond request-smuggling advisory range |
| `c5113b6` | Rendered Markdown/HTML report values as inert content |
| `7430245` | Added share expiry, opaque management IDs, revocation and atomic views |
| `540234c` | Hardened responsive UI, mobile flows, SRI/CSP checks and CI frontend gate |
| `4f9bfd6` | Published verified-backup freshness metrics/checks/alerts |
| `359a80b` | Disabled implicit production migrations without explicit opt-in |
| `dfc9808` | Added immutable release manifests, atomic switch, CSP transition and rollback |
| `049069f` | Prepared non-login runtime identity and `/srv` isolation |
| `13ef89c` | Kept Cloudflare JavaScript Detections under nonce-based strict CSP |

## Validation evidence

- Swift test suite: **161/161 passed** after the final application change.
- Backup checker behavior tests: passed.
- Release-manifest/tamper tests: passed.
- CSP old/new transition tests: passed.
- Frontend integrity: four pages/four inline scripts passed; local executable
  assets exist, SRI matches, inline handlers and persistent bearer tokens fail CI.
- npm audit: **0** known info/low/moderate/high/critical findings.
- Prometheus rules: `promtool` reports three valid rules.
- Bash syntax and ShellCheck: passed for deployment/backup/privileged helpers.
- sudoers fragment: `visudo -cf` passed.
- sysusers/tmpfiles: parsed in dry-run.
- systemd application target: offline exposure **2.8 OK**.
- nginx installed config: syntax succeeds as root.
- live edge CSP/JSD: two unique response nonces matched every injected JSD
  script; four application hashes present and no JavaScript `unsafe-inline`.
- live origin guard: direct and forged-header IPv4 requests return 403;
  Cloudflare, health and onion probes return 200.

The release builder itself was deliberately not run against the live checkout
after these commits: the legacy unit executes `.build/release/Run`, so modifying
that artifact before the controlled cutover would silently change the next
restart candidate. CI must build the exact committed release in isolation.

## CISO forcing questions

### 1. Threat modeling: what are the top three threats?

1. **Web/plugin RCE followed by credential theft or sandbox escape:** likely path
   is untrusted network/provider data through parser/subprocess/runtime, followed
   by same-UID file access; an unrestricted automation key or escape lands in
   the `NOPASSWD: ALL` account. Live `NoNewPrivileges` blocks the simplest direct
   sudo hop, but identity separation is still mandatory.
2. **Loss or disclosure of the investigation database:** likely paths are host
   compromise, flat secret theft, DB credential theft, plaintext backup theft or
   operator error. Encryption helps only while the application key is separate;
   today it is available to the same process as the data.
3. **Availability/data-loss event with no recovery:** backup failures already
   demonstrate detection and recovery gaps. A bad migration, disk loss or
   ransomware event can exceed any unstated RPO/RTO.

### 2. Blast radius and FAIR-style quantification

Current worst-case blast radius is the entire VPS: all OSINT records and secrets,
root control, co-resident services, mail/provider quota abuse and loss of the
only backup copies. The prepared dedicated identity reduces routine app
compromise to one release/process and its scoped DB/provider credentials, but
credential splitting and host segmentation remain necessary.

No defensible annualized loss expectancy is stated because revenue, record
count, contractual penalties, response cost and event-frequency inputs were not
provided. Use `ALE = single-loss expectancy × annual rate of occurrence` for at
least these scenarios: personal-data breach, total DB loss, 24-hour outage,
provider-token abuse and host-wide compromise. Required inputs are record/data
subject count, revenue/hour, restoration labor, notification/legal cost,
provider quota exposure, contractual caps and calibrated frequency ranges.

### 3. Detection and MTTD

Current backup MTTD is effectively human-driven: the job failed repeatedly for
days without a verified page. No central security alert route was demonstrated.

Target detection objectives after rollout:

| Signal | Target MTTD | Mechanism |
|---|---:|---|
| API/nginx unavailable | 2–5 min | Prometheus `up`, external synthetics |
| Backup missing/stale | 10 min after freshness breach | Prepared critical rules + timer failure alert |
| Auth/share/API-key abuse | 15 min | Structured counters and security-event alerts |
| Queue saturation/provider failures | 10 min | Durable queue depth/age and circuit-breaker metrics |
| Unexpected egress/origin bypass | 15 min | Egress proxy and direct-origin synthetic probe |
| Binary/config/SSH/sudo drift | 24 h maximum | Signed release and `/etc`/IAM drift scan |
| Suspected personal-data breach | Immediate human escalation | Pager + incident commander + legal/privacy channel |

### 4. Response, recovery and tabletop

Minimum runbooks must cover: web RCE/root compromise, leaked encryption key,
leaked provider/deploy key, malicious/failed migration, DB corruption/loss,
direct-origin bypass and vendor compromise. Every runbook needs an incident
commander, evidence-preservation step, traffic/worker kill switch, credential
rotation order, stakeholder/legal contacts, restore procedure and closure proof.

Quarterly tabletop scenarios:

1. Compromised plugin executes as the web user: isolate service, preserve logs,
   rotate scoped credentials, validate DB/audit integrity and rebuild host.
2. Database deleted at 03:00: declare RPO/RTO, restore latest full + WAL in an
   isolated environment, validate encryption key and application smoke tests.
3. CI/deploy key stolen: disable GitHub environment/key, inspect release/audit
   trail, rotate SSH host/client credentials and prove current artifact origin.
4. Provider silently changes response to hostile/huge data: quarantine plugin,
   stop egress, replay fixtures and assess stored/report-rendered content.

### 5. Regulatory and notification windows

OSINT findings can be personal data even when sourced publicly. The service
needs documented purpose/legal basis, minimization, retention, access/deletion,
processor inventory and abuse safeguards. Under GDPR Article 33, a qualifying
personal-data breach generally must be notified to the supervisory authority
without undue delay and, where feasible, within **72 hours after awareness**;
Article 34 can require communication to affected people when risk is high.
Counsel/DPO must decide applicability, jurisdictions and exceptions—engineering
must preserve enough evidence to make that decision quickly.

### 6. Vendors and supply chain

At minimum inventory Cloudflare, GitHub Actions, SMTP provider, hosting/DNS,
SwiftPM/GitHub package sources, npm, Ubuntu/container registries, Python packages,
MaxMind/GeoLite, OpenStreetMap tiles, HIBP, Shodan, VirusTotal, AbuseIPDB,
Telegram, Slack, Discord and every OSINT provider contacted by plugins. Record
which target/user data each receives, region/retention, credential scope,
redistribution terms, DPA/SCC requirement, outage behavior, security contact,
version/update source and a rapid disable switch.

Swift dependencies are exactly resolved, and the known SwiftNIO HTTP/2 issue was
updated, but manual advisory checks are not a substitute for continuous vendor
monitoring. Every dependency or provider exception needs an owner and expiry.

## Production acceptance gate

Production is GO only when evidence proves all items below:

- a new encrypted backup passes local verification **and** isolated restore;
- at least one encrypted copy is outside the VPS and protected from overwrite;
- main SPA works under enforced CSP in a real browser with zero CSP errors;
- `swift-vapor` non-login runtime is active and cannot read personal home;
- `micu NOPASSWD: ALL` is gone; automation keys are constrained/revoked;
- production binary/frontend manifest equals the accepted commit;
- explicit migrations complete under the candidate unit and are schema-compatible;
- direct origin is denied while Cloudflare and onion ingress remain healthy;
- PDF, holehe, login, 2FA, one bounded scan, SSE, report and share revocation pass;
- metrics scrape, backup alert delivery and an operator pager acknowledgement pass;
- previous app/frontend/CSP rollback is rehearsed; DB rollback limits are recorded;
- logs/errors/latency are watched for at least one scheduler/watch cycle.

Until then the CISO decision remains **NO-GO / remediation required**.

## Primary references

- [GDPR official consolidated text (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng)
- [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
- [SwiftNIO advisory GHSA-qcc5-f287-vgmq](https://github.com/apple/swift-nio/security/advisories/GHSA-qcc5-f287-vgmq)
- [SwiftNIO HTTP/2 advisory GHSA-q3g2-m552-3r9c](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-q3g2-m552-3r9c)
- [OSV Scanner supported lockfiles/languages](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)
- [GitHub global security-advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories)
