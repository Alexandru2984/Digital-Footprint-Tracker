# Security

> **Current production note (2026-07-20):** this document describes the
> intended repository controls and also retains historical audit notes. The
> dated [extreme security audit](docs/SECURITY_AUDIT_2026-07-20.md) is the
> authoritative source for live-vs-prepared status, open VPS findings and the
> controlled rollout order. A committed mitigation is not considered deployed
> until the rollout evidence is recorded.

This document records the security posture of **Digital Footprint Tracker**:
the trust boundaries the system relies on, the threats considered and how
each one is mitigated in the deployed code, what is intentionally out of
scope, and how to report a vulnerability.

It is intended to be read alongside the code — every claim below points to
the specific file (and where helpful, the commit) that implements the
mitigation. If the claim and the code disagree, the code is the source of
truth and this document is the bug.

---

## Reporting a Vulnerability

If you believe you have found a security issue in this project:

- Email **alex_mihai984@yahoo.com** with the subject line `SECURITY:`.
- Please include: affected URL / endpoint, reproduction steps, expected vs.
  actual behaviour, and the version (commit hash) you reproduced against.
- I will acknowledge within 72 hours and aim to ship a fix or mitigation
  within 14 days. Coordinated disclosure is appreciated — please do not
  publish details before the fix is deployed.
- There is no bug-bounty programme; this is a single-maintainer project.
  Public credit in the README is offered if you would like it.

---

## Trust Model

### Data flow

```
[Internet]
    │
    ▼
[Cloudflare]            ── TLS termination, DDoS / bot filtering, WAF
    │
    ▼
[nginx :443]            ── rate limiting (limit_req_zone), CSP, HSTS,
    │                       X-Frame-Options, security headers,
    │                       strips inbound CF-Connecting-IP / X-Real-IP
    │
    ▼
[Vapor :8085]           ── Sessions middleware, APIKeyMiddleware,
    │                       CSRFMiddleware, CORSMiddleware
    │
    ├── PostgreSQL      ── Fluent ORM (parameterised queries)
    │
    └── Plugin egress   ── SSRFGuard + SafeHTTP (DNS-resolution +
            │               redirect guard) + PluginHTTP (pooled,
            │               retry/backoff, per-host throttle)
            ▼
        External APIs (HIBP, Shodan, VirusTotal, AbuseIPDB,
        GitHub, Gravatar, Telegram, Cloudflare DoH, web.archive.org,
        481 Sherlock sites, SMTP relay,
        user webhook destinations)
```

### Trust levels

| Actor                | What they can do                                                                                  | How abuse is contained                                                                                       |
|----------------------|---------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Anonymous visitor    | View landing page, `GET /api/stats`, `GET /api/share/:token`; create scans; read/export/identity of a scan they created via its unguessable `scanID` (capability) | Per-IP rate limits at nginx + Vapor, with a stricter hourly cap for anon (15/h vs 200/h authed); no transitive pivot for anon scans; capability read only — no enumeration; share tokens 192-bit, hashed at rest |
| Registered user      | Create scans, view their own results, queue/download bounded exports, schedule, tag, configure webhooks, mint API keys | Charset whitelist + SSRF guard on every input; per-user rate limits/quotas; ownership check on every fetch |
| Admin user           | View all scans (with PII masked), audit log, metrics and notification DLQ metadata; replay a DLQ row | Seeded from `.env` only; recent session + `isAdmin` at every admin endpoint; privileged replay is audit-logged |
| Plugin output        | Returns `rawData` strings that the server persists and renders                                    | Byte cap 8 KB; `source`/`type` cap 64 chars; `confidenceScore` clamped `[0.0, 1.0]`; HTML-escaped on render  |
| Webhook destination  | Receives `scan.completed` JSON or notification payloads                                           | SSRF guard rejects internal hosts; HTTPS-only save policy; 10 s timeout; stable delivery ID + bounded retry |
| External plugin host | Receives outbound HTTP from this server                                                           | URLRequest timeouts (10–15 s); URLSession is system TLS; no client secrets sent except per-plugin API keys   |

What is **explicitly not trusted**: any HTTP header that a client could
inject. `X-Forwarded-For` is never used as a source of truth — see
`Request.clientIP` (`Sources/App/Services/RequestContext.swift`) which
trusts `CF-Connecting-IP` (set by Cloudflare, stripped from inbound) then
`X-Real-IP` (set by nginx, stripped from inbound), and falls back to the
socket peer address.

---

## Threats Considered and Their Mitigations

### Web layer (browser ↔ server)

| Threat                          | Mitigation                                                                                       | Reference                                              |
|---------------------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| TLS interception                | Cloudflare TLS + Let's Encrypt on nginx                                                          | `/etc/nginx/sites-enabled/swift.micutu.com`            |
| HSTS downgrade                  | `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`                        | nginx                                                  |
| Clickjacking                    | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`                                         | nginx                                                  |
| MIME sniffing                   | `X-Content-Type-Options: nosniff`                                                                | nginx                                                  |
| Reflected XSS                   | CSP `default-src 'self'`, `script-src 'self'` plus three pinned inline-script SHA-256 hashes      | nginx                                                  |
| **Stored XSS** (diff modal)     | All API values interpolated into `innerHTML` pass through `escapeHtml`                            | `frontend/index.html` `mkSection`; `frontend/admin.js` |
| CSRF                            | `SameSite=Strict` cookies + `CSRFMiddleware`: parses the Origin/Referer and matches the **host exactly** (an earlier `hasPrefix` check let `swift.micutu.com.evil.com` through) on POST/PUT/PATCH/DELETE | `configure.swift`, `Sources/App/Middleware/CSRFMiddleware.swift` |
| Camera / mic / geolocation      | `Permissions-Policy: camera=(), microphone=(), geolocation=()`                                   | nginx                                                  |
| Third-party CDN takeover        | All frontend dependencies bundled locally (d3.min.js, leaflet.css/js, tailwind.css). CSP allows only `'self'` and two specific analytics origins | `frontend/`, nginx                       |

### Authentication & sessions

| Threat                              | Mitigation                                                                                                                                  | Reference                                          |
|-------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| Brute-force login                   | BCrypt cost 12; `AuthRateLimiter` caps 10 attempts per IP per 5 min on `/auth/login` and `/auth/register`                                   | `Sources/App/Services/AuthRateLimiter.swift`       |
| Timing-based user enumeration       | `login` always runs `req.password.async.verify`, falling back to a precomputed dummy BCrypt hash so response time is constant                | `AuthController.swift` (`dummyPasswordHash`)       |
| Register-form user enumeration      | Single generic `409` message for both "username taken" and "email taken"; both DB queries run concurrently for constant response time      | `AuthController.register`                          |
| Session hijacking                   | `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, path `/`); 7-day absolute and 24-hour idle server-side limits                     | `configure.swift`, `SessionSecurityMiddleware`     |
| Session fixation                    | Password login, registration, and successful 2FA delete the old server row and force Vapor to mint a fresh 256-bit session ID              | `SessionSecurity.establishAuthenticated`           |
| Stolen-session sensitive actions    | 10-minute recent-auth window; `/auth/reauth` requires password plus TOTP/recovery code for 2FA accounts; API-key changes, credentials, admin, account export/delete and browser export-job operations require step-up | `SessionSecurity`, controllers |
| Arbitrary-cookie session-table DoS  | Unknown cookie IDs are destroyed instead of being persisted as fresh empty sessions                                                        | `SessionSecurityMiddleware`                        |
| **In-memory session leak**          | Sessions persisted to PostgreSQL via Fluent (`SessionRecord`); restart-survivable; heap-bounded                                              | `configure.swift` (`.use(.fluent)`)                |
| **Bearer API key → session leak**   | Bearer auth uses request-scoped storage and does not even materialize an empty Vapor session; responses carry no session cookie             | `Sources/App/Middleware/APIKeyMiddleware.swift`    |
| API key brute force                 | Tokens stored as SHA-256 hashes (`HashAPIKeyColumn` migration); exact-match indexed DB lookup                                                | `Sources/App/Models/APIKey.swift`                  |
| API key hash leakage in list        | Previously returned first 8 hex chars of the key hash; now masked as `•••`                                                                 | `APIKeyController.swift`                           |
| Stolen/overprivileged API key       | Six explicit scopes, 1–365 day expiry, deny-by-default route policy; account/auth/admin control-plane is session-only; malformed/expired keys fail closed | `APIKeyScopeMiddleware`, `AddAPIKeyAuthorization` |
| Share-link token brute force        | Tokens are 192 bits of `SystemRandomNumberGenerator` output; stored as SHA-256 hashes; configurable expiry; optional Bcrypt password gate    | `ShareController.swift`, `HashSharedReportTokens` migration |

### Authorization

| Threat                                        | Mitigation                                                                                                                                    | Reference                                                                                  |
|-----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| IDOR — read another user's scan               | `Scan.authorizeRead`: an owned scan is owner-only (`scan.user_id == currentUser.id`) on every fetch path (results, stream, export, identity, report, share, diff) | `Sources/App/Services/ScanAccess.swift`, `ScanController`, `ExportController`, `IdentityController`, `ReportController`, `ShareController`, `DiffController` |
| Anonymous-scan access model                   | Ownerless (anonymous) scans are readable by anyone holding the unguessable 122-bit `scanID` — capability access, the share-link model. This replaced the prior admin-only gate, which locked logged-out users out of their own results. Want privacy → scan while signed in. | `Sources/App/Services/ScanAccess.swift` (`Scan.authorizeRead`) |
| Admin escalation                              | `user.isAdmin` re-checked at each `/admin/*` route                                                                                            | `AdminController`, `UserController`, `HealthController.metrics`                            |
| Tag / share / API-key reuse across users      | Every `Tag.find` / `SharedReport.find` / `APIKey.find` is followed by an explicit `entity.user.id == currentUser.id` check                    | `TagController`, `ShareController`, `APIKeyController`                                     |
| API key privilege creep                       | New/unclassified routes are denied to API keys until explicitly mapped to a scope; bearer keys can never call `/account`, `/admin`, or mutating `/auth` routes | `APIKeyScopeMiddleware.swift`                                                    |
| Export-job IDOR / artifact disclosure          | Creation requires an owned scan; every detail/manifest/download/cancel query filters by both job ID and authenticated user ID, returning 404 across tenants; browser calls require recent auth and API keys require `scans:read` | `ExportJobController`, `APIKeyScopeMiddleware` |
| Concurrent recovery-code replay               | Recovery-code removal runs transactionally; PostgreSQL locks the user row with `FOR UPDATE` before decrypt/remove/save                      | `TwoFactorController.consumeRecoveryCode`                                        |

### Input validation

| Threat                                       | Mitigation                                                                                                                                                       | Reference                                                                  |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| SQL injection                                | All data access via Fluent's parameterised query builder. The handful of raw SQL queries (StatsController, dashboard top-sources, hash migrations) take no user input | all controllers                                                            |
| Command injection (holehe subprocess)        | Strict regex `^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,64}$` applied before any subprocess argument substitution; subprocess `environment` is explicit and minimal     | `BulkEmailPlugin.swift`                                                    |
| Mail header injection                        | CR/LF/NUL stripped from `From`, `To`, `Subject`; MIME message built with explicit CRLF separators                                                                 | `EmailService.swift`                                                       |
| **Charset bypass on `/scan/bulk`**           | `InputValidator.validateScanInput` (charset whitelist + length cap + SSRF guard) applied uniformly                                                                | `Sources/App/Services/InputValidator.swift`, `BulkScanController.swift`    |
| **Charset bypass on `/scheduled-scans`**     | Same `InputValidator` at create time **and** at run time in `ScheduledScanRunner` (defense in depth: rejects rows inserted before validator existed)              | `ScheduledScanController.swift`, `ScheduledScanRunner.swift`               |
| Tag colour CSS injection                     | Strict `^#[0-9a-f]{6}$` validation; lowercase-normalised                                                                                                          | `TagController.swift`                                                      |
| Telegram bot-token format                    | `^[0-9]+:[A-Za-z0-9_-]{30,}$`, length ≤ 100, before encryption                                                                                                    | `AuthController.updateSettings`                                            |
| Webhook URL injection                        | `validateWebhookURL`: HTTPS only, SSRF guard on host                                                                                                              | `AuthController.swift`                                                     |

### SSRF (server-side request forgery)

The server initiates outbound HTTP from many places: scan plugins, webhook
delivery, notification dispatch, and the scheduled-scan runner.
Every one of them runs through the same guard.

| Threat                                                       | Mitigation                                                                                                                                          | Reference                                                                                                            |
|--------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| Scan target = internal host                                  | `SSRFGuard.isInternalTarget`/`isInternalURL` reject loopback, RFC1918 (10/8, 172.16/12, 192.168/16), link-local 169.254/16 (cloud metadata), 0.0.0.0/8, CGNAT 100.64/10, IPv6 `::1`/fc/fd/fe80 and IPv4-mapped IPv6; URL hosts also catch numeric obfuscation (decimal `2130706433`, hex, short `127.1`) | `Sources/App/Services/SSRFGuard.swift`, applied via `InputValidator`                                                 |
| **DNS rebinding / host resolves to internal**                | `SafeHTTP` resolves the destination — and every redirect hop — via `getaddrinfo` and refuses if **any** answer is private/loopback/link-local (fail-closed). All user-controlled outbound (webhook, every notification channel, and the WebPosture security-header probe) routes through it; redirects to internal hosts are blocked mid-chain | `Sources/App/Services/SafeHTTP.swift`, `SSRFGuard.resolvesToInternal`                                                |
| **SSRF bypass via scheduled scans**                          | `InputValidator` applied at create time and re-validated by `ScheduledScanRunner` on every cycle (covers rows inserted before validator existed)    | `ScheduledScanController.create`, `ScheduledScanRunner.runDueScans`                                                  |
| Webhook URL → internal host                                  | `validateWebhookURL` enforces HTTPS + structural `isInternalURL` + a resolve-time `resolvesToInternal` check at save; delivery goes through `SafeHTTP` (resolution + redirect guard above)                | `AuthController.swift`, `NotificationDispatcher.sendWebhook`                         |
| Sherlock URL template typo → internal                        | `SSRFGuard.isInternalURL` re-applied on the resolved URL (after `{}` substitution) — defense in depth even though templates are project-controlled  | `BulkUsernamePlugin.swift`                                                                                           |
| Plugin egress to fixed public APIs                           | Routed through `PluginHTTP` (one pooled session, consistent UA, retry/backoff on 429/5xx, per-host throttle). DNS resolved over HTTPS (Cloudflare DoH) rather than a `dig` subprocess | `Sources/App/Services/PluginHTTP.swift`, `Sources/App/Services/DoHResolver.swift`                                   |
| Attack-surface fetch / IP interpolation                      | `WebPosture` fetches only hosts matching `^[a-z0-9.\-]+$` and only via `SafeHTTP.get` (resolution + redirect guard). `InternetDB`/`AttackSurface` interpolate only IPs that passed `isPublicIPv4` (regex + `!isInternalHostname`) into the **fixed** Shodan/crt.sh hosts' path — destination host is never user-controlled, and the upstream `InputValidator` charset (`@._+-` only) blocks query-string injection | `WebPosturePlugin.swift`, `InternetDBPlugin.swift`, `AttackSurfacePlugin.swift`                                     |
| `/api/geolocate` data disclosure / resource abuse           | Auth required, dedicated rate limit (30/min authed, 5/min anon), 4 KB body cap, at most 100 structurally validated entries; lookup is served from a local read-only GeoLite2 database and sends no investigated IPs to a third party | `HealthController.geolocate`, `GeoIP.swift`                                                                          |

The SSRF guard is tested directly — see `testSSRFGuardBlocksLoopbackIPv4`,
`testSSRFGuardBlocksPrivateRanges`, `testSSRFGuardBlocksLinkLocalAndCloudMetadata`,
`testSSRFGuardBlocksIPv6Private`, `testSSRFGuardAllowsPublicHosts`,
`testSSRFGuardURLBlocksInternalHosts`, `testScanEndpointRejectsInternalTarget`,
`testSSRFGuardBlocksNumericIPObfuscation`, `testSSRFGuardDoesNotMisreadNumericUsername`.

### Resource exhaustion and abuse

| Threat                                            | Mitigation                                                                                                                          | Reference                                                                                                |
|---------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| Plugin hang                                       | `ScanPluginRunner` enforces a 120 s `TaskGroup` deadline; cancels remaining plugins on timeout                                      | `Sources/App/Services/ScanPluginRunner.swift`                                                            |
| Cross-request scan fan-out                        | Process-wide execution gate defaults to 3 active + 32 queued full scans; overflow is failed explicitly; configurable with bounded `SCAN_MAX_CONCURRENT` / `SCAN_MAX_QUEUED` | `ScanExecutionGate.swift`, `ScanPluginRunner.run`                                                         |
| Holehe subprocess hang                            | 60 s `DispatchSemaphore` kill timer on the subprocess termination handler                                                            | `BulkEmailPlugin.swift`                                                                                  |
| Scheduled-scan hang                               | Routes through the same `ScanPluginRunner.run` — inherits the 120 s deadline                                                         | `ScheduledScanRunner.swift`                                                                              |
| SSE connection flood                              | Process-wide locked counter, hard cap 30 concurrent streams                                                                          | `ScanController.streamResults`                                                                           |
| SSE replay / database amplification               | Indexed per-scan cursor, strict cursor parser, 100-row replay pages, terminal-only risk calculation, 15 s heartbeat                  | `ScanResultEvent`, `ResultStreamStore`, `ScanController.streamResults`                                   |
| Duplicate/lost notification work                  | Atomic hashed producer key plus unique `(event, channel)` row; PostgreSQL `SKIP LOCKED` lease claims and crash recovery; five bounded attempts by default | `NotificationOutbox`, `NotificationDeliveryWorker`, `CreateNotificationOutbox` |
| Notification retry storm                          | Permanent failures go directly to DLQ; transient failures use capped exponential backoff with deterministic jitter; each tick handles at most ten jobs | `NotificationRetryPolicy`, `NotificationDeliveryWorker` |
| Export/report memory or subprocess amplification   | PostgreSQL-locked per-user quotas, stable paged reads, independent result/source/artifact caps, 30-second PDF deadline, bounded stdout, private temp directory, cancellation-triggered process termination and expiring encrypted artifacts | `ExportJobController`, `ExportArtifactBuilder`, `ExportJobWorker`, `BoundedProcess` |
| Duplicate/stale export publication                 | PostgreSQL `SKIP LOCKED` leases plus lease-owner and `cancel_requested = false` compare-and-set; stale workers cannot overwrite recovered or cancelled jobs | `ExportJobWorker`, `CreateExportJobs` |
| `/scan` flood                                     | nginx `limit_req zone=scan_limit rate=10r/s burst=20`; two stacked Vapor `ScanRateLimiter` windows — 3/min anon, 10/min authed **and** an hourly cap 15/h anon, 200/h authed (per real client IP); anon scans also skip the transitive pivot | nginx, `ScanController.boot`, `ScanRateLimiter.swift`                                                    |
| Candidate fan-out / pivot amplification           | Heavy plugins require verified email and run on at most one candidate; anonymous/unverified scans get light plugins and no pivots; recurring scans also exclude heavy plugins and pivots | `ScanController`, `ScanPluginRunner`, scheduled/watch runners                                             |
| Bulk-scan request amplification                   | Verified account required; ≤10 unique targets; 2 bulk requests/minute and 20/hour; no transitive pivots                              | `BulkScanController`                                                                                      |
| `/auth/*` flood                                   | `AuthRateLimiter` 10 attempts / 5 min                                                                                                | `AuthRateLimiter.swift`                                                                                  |
| `/api/*` generic flood                            | nginx `limit_req zone=api_limit rate=30r/s burst=50`                                                                                  | nginx                                                                                                    |
| `/health` flood → DB-pool starvation              | `ScanRateLimiter(anonMax: 60, authedMax: 120, windowSeconds: 60)`                                                                    | `HealthController.boot`                                                                                  |
| `/share/:token` view-counter spam                 | `ScanRateLimiter(anonMax: 30, authedMax: 60, windowSeconds: 60)`                                                                     | `ShareController.boot`                                                                                   |
| **Scheduled-scan multiplication**                 | Per-user cap of 20 active schedules; `429` on `POST /scheduled-scans` over the limit                                                  | `ScheduledScanController.create`                                                                         |
| Watched-board multiplication                      | Verified account required; ≤25 boards, ≤5 watched boards, ≤3 active entities/cycle; board shape capped at 500 nodes/1,000 edges       | `InvestigationController`, `InvestigationWatchRunner`                                                     |
| **PDF report stdout OOM**                         | 20 MB stdout cap with chunked streaming; subprocess `terminate()` if exceeded; `413` to client                                       | `ReportController.swift`                                                                                 |
| **`/my-scans` / `/admin/scans` OOM**              | DB-level `.count()` + `.range()` pagination; search path bounded to 500 candidates                                                   | `UserController.swift`                                                                                   |
| **`/admin/dashboard` top-source OOM**             | Raw SQL `GROUP BY source ORDER BY count DESC LIMIT 10` (same pattern as `StatsController`)                                            | `AdminController.dashboard`                                                                              |
| Request body size                                 | nginx `client_max_body_size 10k` on `/api/*`; `/api/geolocate` 4 KB app-level cap                                                    | nginx, `HealthController.geolocate`                                                                      |

### Secrets management

| Threat                                       | Mitigation                                                                                                                              | Reference                                                                       |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| `.env` world-readable                        | Mode `0600` enforced manually                                                                                                            | `ls -la .env`                                                                   |
| **SMTP credentials visible in `ps`**         | curl invoked with `--netrc-file /tmp/smtp-<uuid>.netrc` (mode `0600`, deleted on `defer`); never `--user user:pass` in argv               | `Sources/App/Services/EmailService.swift`                                       |
| API keys plaintext at rest                   | SHA-256 hashed; raw token shown once on creation                                                                                          | `HashAPIKeyColumn` migration; `APIKey.swift`                                    |
| Share-link tokens plaintext at rest          | SHA-256 hashed                                                                                                                           | `HashSharedReportTokens` migration; `SharedReport.swift`                         |
| Sensitive fields plaintext at rest           | Dual-read v1/v2 AES-256-GCM envelopes cover scan/result/board data, notification credentials, schedules, inbox/outbox payloads, export artifacts/manifests, audit details, and cache payloads; v2 authenticates field + row UUID as AAD | `TokenEncryption`, `FieldCrypto`, `MigrateSensitiveFieldEncryption`             |
| Encryption/index key reuse                   | V2 derives independent encryption and blind-index keys with HKDF-SHA256                                                                  | `TokenEncryption`                                                               |
| Accidental encryption-key replacement        | Key IDs plus a persistent encrypted marker verify the active/previous bounded keyring before traffic starts                             | `EncryptionKeyVerifier`, `CreateEncryptionMetadata`                             |
| Interrupted/concurrent key rotation          | UUID-cursor checkpoint is atomic with each row-locked batch; PostgreSQL advisory lock rejects a second runner; active-key-only verify stage gates old-key removal | `SensitiveFieldRewrapper`, `CryptoRewrapCommand`, `docs/ENCRYPTION_KEY_ROTATION.md` |
| Cache target dictionary attacks              | Normalized targets use keyed blind indexes; rotation queries a bounded active/previous candidate set and payload JSON is encrypted       | `PluginCacheStore`                                                              |
| Secrets in app logs                          | PII masked at INFO: `***@domain.com` for emails, `use***` for usernames                                                                  | `ScanController.scan`                                                           |
| Secrets in audit log                         | Audit log stores `action` + truncated `target` (200 chars) + IP — never request bodies, never tokens                                      | `Sources/App/Services/AuditLogger.swift`                                        |

### Data retention and privacy

| Threat                                            | Mitigation                                                                                                                              | Reference                                                                  |
|---------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| Indefinite scan retention                         | Daily `ScanCleanupLifecycle`: anonymous scans 30 d; per-user retention = `user.retentionDays ?? 30`                                      | `Sources/App/Services/ScanCleanupLifecycle.swift`                          |
| **Retention policy bypass**                       | Cleanup no longer runs a hard 30-day global delete before per-user policy applies — fixed so 90/365-day users actually keep their data    | same file                                                                  |
| Audit log unbounded growth                        | Daily prune of `audit_logs` rows older than 90 days                                                                                      | same file                                                                  |
| Session table unbounded growth                    | Daily prune of `_fluent_sessions` rows older than 30 days (the `.fluent` driver never expires them); `created_at` added by a defensive migration | `ScanCleanupLifecycle.swift`, `AddSessionCreatedAt` migration              |
| Notification outbox unbounded growth              | Hourly bounded sweep removes only terminal events older than 30 days by default; pending/leased rows are retained; user/scan deletion cascades | `NotificationDeliveryWorker`, `CreateNotificationOutbox` |
| Cross-user PII in admin views                     | `maskInput()` applied even for admin viewing `/admin/scans` (`***@domain.com`, `use***`)                                                  | `UserController.adminScans`                                                |

### Infrastructure

| Threat                                       | Mitigation                                                                                                                                                                                            | Reference                                                                            |
|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|
| Process escape on host                       | systemd hardening drop-in: `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`, `NoNewPrivileges`, `LockPersonality`, `RestrictSUIDSGID`, `ProtectKernelTunables/Modules/Logs/ControlGroups/Clock`, `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `RestrictNamespaces`, `RestrictRealtime`, `SystemCallArchitectures=native`, `RemoveIPC` | `/etc/systemd/system/swift-vapor.service.d/10-hardening.conf`                        |
| Running as root                              | `User=micu` / `Group=micu` in systemd unit                                                                                                                                                            | `/etc/systemd/system/swift-vapor.service`                                            |
| Reverse-proxy header trust                   | nginx strips inbound `CF-Connecting-IP` / `X-Real-IP` and sets its own values; app reads via `Request.clientIP` helper                                                                                | nginx, `Sources/App/Services/RequestContext.swift`                                   |
| Client IP spoofing in rate-limit / audit     | Resolution order: `CF-Connecting-IP` → `X-Real-IP` → socket peer; raw `X-Forwarded-For` never trusted                                                                                                 | `Request.clientIP` (used by `ScanRateLimiter`, `AuthRateLimiter`, `AuditLogger`, `ScanController.scan`) |
| Service exposure score                       | `systemd-analyze security swift-vapor` returns `5.2 MEDIUM` (down from 9.x UNSAFE pre-hardening)                                                                                                       | run the command on the host                                                          |

---

## Recent Security Audit (May 2026)

A line-by-line security review was performed across the entire backend
(`Sources/App/`), the frontend SPA (`frontend/index.html`,
`frontend/admin.js`), the nginx vhost, and the systemd unit. **30 findings**
were filed:

| Severity     | Count | Status                                                                                                  |
|--------------|------:|---------------------------------------------------------------------------------------------------------|
| 🚨 Critical | 1     | Fixed                                                                                                   |
| 🔴 High     | 11    | Fixed                                                                                                   |
| 🟡 Medium   | 19    | 16 fixed; 3 intentionally skipped — 2 incidental in higher-severity fixes, 1 cosmetic (M-19)            |
| 🟢 Low      | 8     | 2 fixed (L-1, L-6); 6 deferred with documented rationale                                                |
| 🔵 Info     | 14    | I-1 (systemd hardening) and I-13 (audit retention) actioned; rest were already in place pre-audit       |

Selected fixes (every one of these is a separate commit, viewable via
`git log --grep='fix(security)'`):

- **`fix(security): make Bearer API key auth stateless`** — `APIKeyMiddleware`
  wrote to in-memory sessions on every Bearer request → unbounded memory
  growth. Migrated to request-scoped `req.storage`.
- **`fix(security): close SSRF bypass via scheduled scans`** — input
  validation extracted to `InputValidator` and applied uniformly across
  `/scan`, `/scan/bulk`, and `/scheduled-scans` (create + run time).
- **`fix(security): escape user-controlled data in diff modal`** —
  stored XSS via `r.rawData` interpolated into `innerHTML` without
  escaping; now via `escapeHtml`.
- **`fix(security): harden /api/geolocate`** — was an unauthenticated
  cleartext third-party proxy; now auth + rate limit + body cap + bounded
  JSON shape checks and fully offline GeoLite2 lookups.
- **`fix(security): write SMTP credentials to a private netrc file`** —
  curl creds were visible in `ps`; now mode-0600 `--netrc-file`.
- **`fix(security): respect per-user retentionDays in cleanup job`** —
  global 30-day delete ran before per-user retention, destroying data
  of users with 90/365-day retention.
- **`fix(security): equalise /auth/login response time`** — BCrypt verify
  now always runs (dummy hash if user missing) to block timing-based
  username enumeration.
- **`fix(security): unify register error message`** — single 409
  message + concurrent uniqueness checks; no more enumeration via the
  `Username taken` / `Email registered` distinction.
- **`fix(security): persist sessions in PostgreSQL via Fluent`** —
  sessions survive restart and are heap-bounded rather than
  memory-resident.
- **`hardening: bundle Leaflet locally + remove unpkg from CSP +
  systemd hardening drop-in`** — eliminates CDN supply-chain risk and
  applies process isolation directives.

## June 2026 hardening + OSINT-engine pass

A second pass (a code review of the same surface plus a large OSINT-engine
expansion) shipped these security-relevant changes — each a separate commit:

- **SSRF hardened from a string check to resolution-based.** The old guard
  only string-matched the hostname, so a public name with an internal DNS
  record (or a numeric-obfuscated host) bypassed it. `SafeHTTP` now resolves
  every destination (and redirect hop) via `getaddrinfo` and fail-closes on any
  private answer; `SSRFGuard` additionally recognises numeric/hex/short IPv4,
  IPv4-mapped IPv6, 0.0.0.0/8 and CGNAT. All user-controlled egress routes
  through it.
- **CSRF Origin check tightened** from `hasPrefix` (defeated by
  `swift.micutu.com.evil.com`) to exact host match.
- **Cross-tenant scan dedup leak fixed.** `/scan` reused a completed scan by
  input *without* scoping to the requester, returning another user's scanID and
  results inline; dedup is now owner-scoped.
- **Anonymous-scan access model** changed from admin-only (which locked
  logged-out users out of their own results) to capability access via the
  unguessable `scanID`, with stricter anon limits (hourly cap, no pivot).
- **Session table pruning** added (the `.fluent` driver never expired rows).
- **API-key `lastUsedAt` debounced** (was a DB write per authenticated request).
- **`dig` subprocess removed** from `DomainPlugin` in favour of DNS-over-HTTPS,
  shrinking the subprocess surface (only the `whois` and `holehe` subprocesses
  remain, both already argv-array / regex-gated).

New outbound surfaces (Cloudflare DoH, web.archive.org, Gravatar profile JSON,
GitHub events) all go through `PluginHTTP`/`SafeHTTP` and the same SSRF guard.

### Attack-surface, monitoring & reporting pass — security review

A further expansion (Shodan-grade exposure via InternetDB, whole-footprint
attack-surface mapping, web-posture grading, exposure-diff monitoring, and
shareable Markdown/HTML reports) was audited end-to-end; no exploitable issues
were found. The relevant properties:

- **New fixed-host egress.** `InternetDB` (`internetdb.shodan.io`), the `crt.sh`
  enumerator and `AttackSurface` target hosts the project controls; only IPs that
  passed `isPublicIPv4` (dotted-quad regex + `!SSRFGuard.isInternalHostname`) are
  interpolated into a URL path, and the upstream `InputValidator` charset
  (`@._+-` only) makes query-string injection impossible. All route through
  `PluginHTTP`.
- **Typosquat lookalike recon stays on a fixed host.** `Typosquat` generates
  permutations of the target domain and resolves each only via `DoHResolver`
  (Cloudflare DoH, `cloudflare-dns.com` — project-controlled), with the candidate
  carried as the `name` query param, never as the request host. Permutations are
  validated as RFC-1123 hostnames before any lookup and the lookup count is capped
  (`maxCandidates`), so there is no SSRF surface and no unbounded fan-out.
- **New user-controlled egress.** `WebPosture` fetches the scan target's web host
  to grade its security headers; it restricts the host to `^[a-z0-9.\-]+$` and
  fetches **only** via `SafeHTTP.get`, which inherits the same pre-flight
  resolution + redirect re-validation as webhook delivery (SSRF fail-closed).
- **Server-rendered HTML report is XSS-safe.** `GET /export/:id/report.html`
  reflects scan data into a same-origin page; every interpolated value is
  HTML-escaped (`& < > " '`), all dynamic data lands in text context (no
  attribute / `href` / `<script>` sinks), and the document carries inline
  `<style>` only — no inline script. The SPA opens it with
  `window.open(…, 'noopener')`. Verified by `testExecutiveReportHTMLEscapesAndStructures`.
- **Exports & identity are capability-gated.** Every `/export/:id*` and
  `/identity/:id` handler calls `Scan.authorizeRead`; `/scans/:id/exposure-diff`
  is owner-only and diffs only the requester's own prior scans of the same input.
- **Durable exports are not anonymous capabilities.** `/export-jobs*` requires
  an authenticated owner, filters every query by `user_id`, encrypts both output
  and manifest, validates integrity before attachment download, and cannot
  publish after a cancellation wins the database CAS.

Accepted low-severity notes (defense-in-depth, not exploitable): `SafeHTTP.get`
reads the full response body (bounded by the 15 s resource timeout, as
`SafeHTTP.post` already does); the **Markdown** report does not neutralise
Markdown link syntax in cell text — the print-ready **HTML** report (the default
UI path) is fully escaped, and Markdown viewers sanitise `javascript:` links.

### Out-of-scope deliberate skips

These are documented choices, not oversights:

- **Email-verification registration flow.** Today registration succeeds
  immediately; combined with the unified `409` we leak existence of an
  account when a probe tuple `(random_username, victim_email)` collides.
  Closing this fully requires a token-confirmation flow and SMTP-deliverable
  guarantee that the project does not yet have.
- **MFA / TOTP.** Single-user admin, low-volume site. Cost > benefit.
- **Formal coordinated-disclosure programme / bug bounty.** Single
  maintainer.
- **Audit-log immutability.** `audit_logs` is a regular Postgres table —
  an admin could delete rows. Append-only enforcement would require a
  separate database role or external WORM storage.
- **Offline GeoIP data freshness.** Geolocation no longer discloses scan IPs
  to a third party. Operators must periodically refresh the local GeoLite2
  City/ASN files; stale files reduce result accuracy but do not expand egress.
- **Cross-DB-dialect-portable hash migrations.** `HashAPIKeyColumn` and
  `HashSharedReportTokens` use PostgreSQL-specific DDL
  (`ADD COLUMN IF NOT EXISTS`, `ALTER COLUMN SET NOT NULL`,
  `ADD CONSTRAINT`). Tests use SQLite and skip those migrations; no test
  currently exercises the affected models. Documented in
  `Tests/AppTests/AppTests.swift`.
- **`MemoryDenyWriteExecute=yes` in systemd hardening.** Swift's runtime
  may JIT or use writable-executable mappings in some configurations;
  enabling this would need empirical validation under load.

---

## Operator Configuration Checklist

For anyone deploying this stack on their own host:

- [ ] `.env` permissions are `0600`
- [ ] `ADMIN_PASSWORD` is a high-entropy value (not the example)
- [ ] `ENCRYPTION_KEY` is set to exactly 64 hex characters (32 bytes).
      Production aborts startup when it is absent, malformed, or does not
      match the persistent key-check marker. Back it up separately before
      deployment; losing it makes encrypted data unrecoverable.
- [ ] `ENCRYPTION_KEY_ID` is stable and unique for the active root key;
      `ENCRYPTION_WRITE_VERSION` remains `1` until every process has the dual
      reader. Any `ENCRYPTION_PREVIOUS_KEYS` value is supplied through the
      secret channel, contains at most four `id=64hex` entries, and is removed
      only after rewrap verification.
- [ ] Before key/format rotation, the backup has been restored, the whole fleet
      uses one explicit writer configuration, and the full command plus a
      separate `--verify-only` pass from the accepted release are archived.
      Follow `docs/ENCRYPTION_KEY_ROTATION.md`; never roll an old binary onto v2.
- [ ] `ALLOWED_ORIGIN` in production matches the exact public origin
- [ ] nginx CSP `script-src` SHA-256 hashes are regenerated after any
      change to the inline `<script>` block (see deployment notes in
      README)
- [ ] Cloudflare proxy (orange-cloud) is enabled on the public DNS record
- [ ] Let's Encrypt auto-renewal is configured
- [ ] systemd hardening drop-in is in place — verify with
      `systemctl cat swift-vapor` (should include
      `10-hardening.conf`) and `systemd-analyze security swift-vapor`
      (target ≤ 6.0)
- [ ] No stray `.env.bak*` files in the working directory (gitignored
      but they accumulate locally)
- [ ] The `swift-vapor.service` runs as a non-root user

---

*Last reviewed: 2026-06-13. Material change to this document should
accompany the corresponding code change in the same commit.*
