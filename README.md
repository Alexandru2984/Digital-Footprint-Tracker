# Digital Footprint Tracker

[![CI](https://github.com/Alexandru2984/Digital-Footprint-Tracker/actions/workflows/ci.yml/badge.svg)](https://github.com/Alexandru2984/Digital-Footprint-Tracker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Swift](https://img.shields.io/badge/swift-6.2-orange.svg)](https://swift.org)
[![Live Demo](https://img.shields.io/badge/demo-swift.micutu.com-success.svg)](https://swift.micutu.com)

**OSINT aggregation engine** that scans an email address, username, domain, IP,
or phone number across 500+ sources in parallel, streams results live via
Server-Sent Events, and renders them as an interactive force-directed identity
graph.

🔗 **Live demo:** <https://swift.micutu.com>  ·  **Interactive API:** <https://swift.micutu.com/docs/>

---

## Highlights

- **Production-hosted** on Ubuntu behind nginx + Cloudflare. The hardened
  systemd, backup and atomic-release configuration is prepared in the repository,
  but the live recovery/configuration gaps are rollout blockers—not completed
  controls. See the current
  [`security audit`](docs/SECURITY_AUDIT_2026-08-12.md),
  [`rollout runbook`](docs/PRODUCTION_ROLLOUT.md) and
  [`roadmap`](docs/ROADMAP.md).
- **25 OSINT plugins** orchestrated by a `TaskGroup` with a hard 120 s
  deadline; results streamed live via SSE as each plugin completes.
- **Cross-plugin result cache** with per-plugin TTL (1 h for volatile threat
  intel, 24 h for breach data) — cuts external API calls dramatically on
  repeated scans of the same target.
- **GDPR self-service** — every user can request an account data bundle
  (`GET /account/export`) or permanently delete it with confirmation-gated
  `DELETE /account`.
- **Prometheus `/metrics`** endpoint (text exposition 0.0.4) — scan counts by
  status, cache hit/miss ratio, notifications dispatched by channel. Bearer
  token auth via `METRICS_TOKEN` env var so scrapers don't need an admin
  session.
- **Multi-channel monitoring** for scheduled scans — Discord, Telegram, Slack,
  email, generic webhook — silent by default, with enriched diff messages
  that list which sources surfaced new findings.
- **Hermetic test suite** running on every push (`swift test` in CI with
  in-memory SQLite; 161 tests at the August 2026 audit), SwiftLint enforced, OpenAPI 3 spec
  rendered as a hosted Swagger UI.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Swift 6.2 toolchain + Vapor 4 (async/await, `TaskGroup` concurrency) |
| Database | PostgreSQL (Fluent ORM, 19 migrations) |
| Frontend | Vanilla JS + Tailwind CSS + D3.js v7 + Leaflet |
| Reverse proxy | nginx (rate limiting, CSP, HSTS, security headers) |
| Deployment | systemd (`swift-vapor.service`) on Ubuntu VPS, optional Docker Compose |
| Network | Cloudflare DNS + proxy (DDoS shield, TLS termination) |
| Observability | Prometheus-compatible `/metrics`, structured `swift-log` |
| Email | Raw SMTP (Mailcow / SendGrid compatible) |
| Tests + Lint | XCTest, SwiftLint, GitHub Actions CI |

---

## Architecture

```
Browser
  │
  ▼
Cloudflare (TLS termination, DDoS protection)
  │
  ▼
nginx (rate limiting, CSP, HSTS, XSS headers)
  │  /api/*  →  strip prefix  →  Vapor :8085
  │  /*      →  static files (frontend/)
  ▼
Vapor 4
  ├── Middleware: Sessions, APIKey, CSRF, CORS, NoCache
  ├── Controllers (16)
  │     ScanController, StatsController, AuthController, UserController,
  │     AdminController, APIKeyController, BulkScanController,
  │     CorrelationController, DiffController, ExportController,
  │     HealthController, NotificationController, ReportController,
  │     ScheduledScanController, ShareController, TagController
  └── Plugin Pipeline — parallel TaskGroup, 120s timeout
        Email     → GravatarCheck, HaveIBeenPwned, Pastebin, BulkEmailOSINT (holehe)
        Username  → GitHub, GitLab, Reddit, Twitter, Keybase, Telegram,
                    Mastodon, HackerNews, Steam, Npm, PyPI, BulkOSINT (Sherlock 481)
        Domain/IP → DomainOSINT (DNS+WHOIS+geo), CertificateTransparency (crt.sh),
                    PassiveDNS, Shodan, VirusTotal, AbuseIPDB, WHOIS
        Phone     → PhoneOSINT (AbstractAPI)
  │
  ▼
PostgreSQL
  ├── users           (id, username, email, password_hash, is_admin,
  │                    retention_days, webhook_url, notify_*, created_at)
  ├── scans           (id, input, status, created_at, completed_at, user_id FK)
  ├── results         (id, scan_id, source, type, confidence_score, raw_data)
  ├── tags / scan_tags
  ├── scheduled_scans
  ├── scan_notifications
  ├── api_keys        (SHA-256 hashed token)
  ├── shared_reports  (hashed token, expires_at)
  └── audit_logs
```

---

## Features

### OSINT Engine (25 plugins, 500+ sources)
- **Email** — Gravatar, HaveIBeenPwned (breaches + pastes), Pastebin, holehe (400+ sites)
- **Username** — GitHub (enriched: name/bio/location/Twitter), GitLab, Reddit, Twitter/X, Keybase, Telegram, Mastodon, HackerNews, Steam, npm, PyPI, Sherlock (481 sites)
- **Domain / IP** — DNS A/MX/TXT/SPF + reverse PTR + WHOIS + IP geolocation, **certificate transparency (crt.sh)**, **passive DNS**, **Shodan**, **VirusTotal**, **AbuseIPDB**
- **Phone** — E.164 detection, carrier + country via AbstractAPI
- **Parallel execution** — all plugins run concurrently in a Swift `TaskGroup` with a 120 s hard timeout
- **Risk score** — confidence-weighted aggregate (Low / Medium / High / Critical) with breach + credential findings weighted 3×

### Authentication & Access Control
- Register / Login / Logout — session-based (HttpOnly + Secure + SameSite=Strict cookie)
- Admin seeded from `ADMIN_USERNAME` + `ADMIN_PASSWORD` on first start
- **My Scans** — authenticated users see their own scan history
- **Admin panel** (`/admin.html`) — full scan history + per-user stats
- BCrypt password hashing (cost factor 12)
- Auth rate limiting on `/auth/login` and `/auth/register`
- CSRF middleware on state-changing requests

### API Keys
- Per-user API keys, **stored as SHA-256 hashes** (cleartext shown once on creation)
- Bearer auth via `Authorization: Bearer <key>` with deny-by-default route authorization
- Six least-privilege scopes: `scans:read`, `scans:write`, `automation:read`,
  `automation:write`, `investigations:read`, `investigations:write`
- Keys expire after 1–365 days (90 by default); account/admin/auth controls are
  always browser-session-only, regardless of scope
- Issue / revoke endpoints under `/api/auth/api-keys`

> Security migration note: API keys created before scoped expiry support have
> no expiry timestamp and are rejected after upgrade. Reissue them deliberately.

### Scheduled & Bulk Scans
- **Scheduled scans** — hourly / daily / weekly recurrence, run via `ScheduledScanRunner` lifecycle hook
- **Bulk scan** — submit a list of inputs in one request, scans run in parallel
- **Diff** — compare two scans of the same target to see what changed

### Notifications
- Webhook (per-user URL), Discord, Telegram, Slack, SMTP email
- Per-channel toggles stored on the user (`notify_discord`, `notify_telegram`, etc.)

### Shareable Reports
- Generate a public link to any scan; token is **stored hashed**, expires after a configurable window
- PDF generation server-side via `scripts/generate_report.py`

### Real-time Streaming
- **Server-Sent Events** — results appear live as each plugin finishes
- Automatic fallback to 3-second polling if SSE unavailable
- SSE connection limit (30 concurrent) via `NIOAtomic` counter

### Frontend
- **Stats dashboard** — total scans, last 24 h / 7 d activity, top sources bar chart
- **Identity graph** — D3.js v7 force-directed; centre = target, leaves = sources, edge colour = confidence
- **Filters & sorting** — by type (social_media, breach_data, dns_record, …), confidence, source A–Z
- **Exports** — CSV, JSON, PDF
- **Dark / light mode**, keyboard shortcuts, mobile-responsive
- Share link, force-rescan (bypass cache), input-type auto-detection (EMAIL / USERNAME / DOMAIN / PHONE)
- Scan history in localStorage (last 20 scans)

### Security
- **CSP** with inline-script hash, `'self'`-only sources
- `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `X-Robots-Tag: noindex`
- nginx rate limiting: 10 req/s on `/scan`, 30 req/s on all API routes
- Input sanitisation: character whitelist + 255-char limit before any plugin runs
- `rawData` capped at 8 KB, `source`/`type` at 64 UTF-8 bytes, `confidenceScore` clamped `[0.0, 1.0]`
- All plugins use `URLSession` (Foundation) — safe from Vapor lifecycle races
- Holehe subprocess bounded by a 60 s kill timer via `DispatchSemaphore`
- PII masked in audit logs: `***@domain.com`, `use***`
- **API keys & share-report tokens stored hashed**, never in plaintext
- Session IDs rotate after password and 2FA authentication; the old server row
  is deleted. `__Host-` cookies expire after 7 days with a 24-hour idle limit.
- Sensitive controls use a 10-minute step-up window refreshed via
  `POST /api/auth/reauth` (password plus TOTP/recovery code when 2FA is enabled).
- Disabling 2FA requires the password and a fresh TOTP/recovery code, consumes
  the factor once, and rotates the authenticated session.
- Versioned AES-256-GCM envelopes for scan targets/results, investigation
  boards, notification credentials, scheduler targets, notifications, audit
  details, and plugin-cache payloads. V2 derives separate encryption and blind-
  index keys with HKDF-SHA256, embeds a key ID, and authenticates the storage
  field plus row UUID as AAD. Readers accept v1 and v2 during staged rotation;
  production refuses to boot without a valid keyring and verifies a persistent
  marker before serving traffic.
- SMTP header-injection guard (CRLF stripped from `From` / `To` / `Subject`)
- Per-user `retention_days` + daily `ScanCleanupLifecycle` (default 30 d)

---

## API Reference

The full OpenAPI 3 spec is served at **`/openapi.yaml`** and rendered as an
interactive explorer at **`/docs/`** (Swagger UI, bundled locally — no CDN).
Open it in a browser to try requests against the live API straight from the
page (cookie auth is persisted across reloads).

### Core
- `POST /api/scan` — start scan or return cached result. `{ "input": "...", "force": false }`
- `GET  /api/stream/:id` — SSE stream of `PluginResult` events
- `GET  /api/results/:id` — full scan result
- `GET  /api/stats` — aggregate stats

### Auth
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/reauth` — refresh recent authentication for sensitive actions
- `POST /api/auth/2fa/disable` — requires both the current password and a fresh TOTP/recovery code
- `GET  /api/auth/me`

### User
- `GET /api/my-scans` — last 50 scans for the authenticated user (input masked)
- `GET /api/admin/scans` — last 100 scans across all users (admin only)

### Other route groups
`/api/auth/api-keys`, `/api/scheduled-scans`, `/api/scan/bulk`, `/api/share`, `/api/diff`,
`/api/correlate`, `/api/tags`, `/api/notifications`, `/api/export`, `/api/report/:id`, `/api/health`

Bulk scans, recurring scans, heavy plugins, and watched-board monitoring require
a verified account. Bulk requests accept at most 10 unique targets and are capped
at 2 requests/minute and 20/hour per account.

---

## Local Setup

### Option A: Docker (zero local toolchain)

```bash
cp .env.docker.example .env        # then edit values (passwords + ENCRYPTION_KEY)
docker compose up -d --build       # builds image, starts Postgres + app
open http://localhost:8085
```

The app container runs read-only, dropped capabilities, non-root user, with `/tmp` on tmpfs.
Postgres data persists in the `pgdata` named volume.

Encryption rollout is reader-first: leave `ENCRYPTION_WRITE_VERSION=1` for the
first deployment, give the active key a stable `ENCRYPTION_KEY_ID`, and switch
writes to `2` only after every web/worker process runs the dual reader. During a
key change, expose the old root only through the bounded
`ENCRYPTION_PREVIOUS_KEYS=id=64hex` keyring. Treat that variable exactly like the
active key; it must not be committed, logged, or retained after verified rewrap.

### Option B: Native build

#### Prerequisites
- Swift 6.2 toolchain
- PostgreSQL
- Python 3 venv populated from the hash-locked `requirements-runtime.txt`
  (`fpdf2` reports + [holehe](https://github.com/megadose/holehe))

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes --requirement requirements-runtime.txt
```

### 1. Clone & configure

```bash
git clone https://github.com/Alexandru2984/Digital-Footprint-Tracker
cd Digital-Footprint-Tracker
cp .env.example .env   # then edit values
```

**.env** — minimal set:
```
PORT=8085
DATABASE_HOST=localhost
DATABASE_USERNAME=footprint_user
DATABASE_PASSWORD=your_password
DATABASE_NAME=footprint_db
HOLEHE_PATH=/home/micu/swift+vapor/.venv/bin/holehe
REPORT_PYTHON_PATH=/home/micu/swift+vapor/.venv/bin/python3
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=your_strong_password
# Optional plugin keys:
HIBP_API_KEY=...
ABSTRACT_PHONE_API_KEY=...
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
# Optional SMTP for email notifications:
SMTP_HOST=...
SMTP_PORT=587
SMTP_USER=...
SMTP_PASS=...
SMTP_FROM=noreply@example.com
```

### 2. Build & run

```bash
swift build -c release
swift run Run serve        # migrations run automatically on startup
```

### 3. Tests

```bash
swift test --enable-test-discovery
```

---

## Project Structure

```
Sources/App/
├── Controllers/        — 16 controllers (Auth, Scan, Stats, Admin, APIKey,
│                         BulkScan, Correlation, Diff, Export, Health,
│                         Notification, Report, ScheduledScan, Share,
│                         Tag, User)
├── Middleware/         — APIKeyMiddleware, CSRFMiddleware
├── Migrations/         — 18 migrations
├── Models/             — User, Scan, Result, Tag, ScanTag, ScheduledScan,
│                         ScanNotification, APIKey, SharedReport, AuditLog
├── Plugins/            — 25 OSINT plugins + sherlock_data.json (481 sites)
├── Services/           — AuditLogger, AuthRateLimiter, EmailService,
│                         NotificationDispatcher, RiskScorer, TokenEncryption,
│                         ScanCleanupLifecycle, ScanProgressTracker,
│                         ScanRateLimiter, ScheduledScanRunner, NoCacheMiddleware
├── configure.swift
└── routes.swift
frontend/
├── index.html              — single-page app
├── admin.html / admin.js   — admin dashboard
├── login.html / register.html
├── openapi.yaml            — full API spec
├── tailwind.css            — compiled Tailwind (SRI hash in HTML)
└── d3.min.js               — D3.js v7 (local, no CDN)
scripts/
└── generate_report.py      — server-side PDF report generator
Tests/AppTests/AppTests.swift  — 27 XCTests
```

---

## Adding a New Plugin

1. Create `Sources/App/Plugins/YourPlugin.swift`:

```swift
struct YourPlugin: FootprintPlugin {
    let name = "YourSource"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        // return [] to skip, or [PluginResult(...)] for a hit
    }
}
```

2. Add it to the `plugins` array in `ScanController.swift`. Plugins run concurrently — no further wiring required.

---

## Deployment (production)

Production uses immutable, commit-named bundles under
`/srv/swift-vapor/releases/` and a single `/srv/swift-vapor/current` symlink
shared by systemd and nginx. The forced
SSH command runs `scripts/deploy.sh`; it refuses dirty/diverged source, requires
a recent verified encrypted backup, builds from `git archive`, runs migrations
through a sandboxed oneshot unit, transitions CSP hashes, switches the symlink,
and verifies both backend and served frontend. A failure restores the prior
release automatically (database migrations are intentionally never auto-reverted).

The initial conversion from the legacy live checkout is a privileged maintenance
operation. Follow `docs/PRODUCTION_ROLLOUT.md`; do not point nginx/systemd at the
new symlink until its release manifest passes `scripts/release-lib.sh` validation.

### Database backups

`scripts/backup.sh` streams `pg_dump | gzip` directly into authenticated
AES-256 GPG encryption, then verifies decryption and gzip integrity before the
partial file becomes a retained backup. No plaintext dump is written to disk.
It writes to `/home/micu/swift-vapor-backups/` and keeps the last 7 encrypted
dumps by default (`BACKUP_RETENTION` may be set from 1 to 365).
The accompanying `swift-vapor-backup.service` + `.timer` units run it daily
at 02:00 UTC with a 10-minute jitter and `Persistent=true` so a missed run
catches up on next boot.

Create a random encrypted systemd credential, then install the units once. The
application service cannot read this backup passphrase:

```bash
openssl rand -base64 48 | sudo systemd-creds encrypt --name=backup-passphrase - /etc/credstore.encrypted/swift-vapor-backup-passphrase
sudo cp scripts/swift-vapor-backup.service scripts/swift-vapor-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now swift-vapor-backup.timer
sudo systemctl list-timers swift-vapor-backup.timer    # confirm next trigger
```

Trigger an on-demand backup and confirm that verification completed:

```bash
sudo systemctl start swift-vapor-backup.service
sudo journalctl -u swift-vapor-backup.service -n 30 --no-pager
scripts/check-backup.sh --status-file /var/lib/swift-vapor-backup/last-success
```

The backup job publishes `/var/lib/swift-vapor-backup/last-success` only after
authenticated decryption and gzip verification succeed. The read-only checker
also verifies that the newest encrypted dump exists, is private, is non-trivial
in size and is recent. It is a freshness gate, not a restore test; exercise a
real restore into an isolated PostgreSQL instance on a schedule.

Existing `.sql.gz` files are plaintext and are deliberately not deleted or
rewritten by the new job. Re-encrypt and verify them during the controlled
rollout. Keep at least one tested, encrypted copy off the VPS; local rotation
alone does not cover disk loss or total host compromise.

### Prometheus scraping

`/metrics` exposes counters + gauges in Prometheus text format
(`text/plain; version=0.0.4`). Set `METRICS_TOKEN` in `.env` to a random
secret, then point your Prometheus at it:

```yaml
scrape_configs:
  - job_name: swift-vapor
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets: [swift.micutu.com]
    authorization:
      type: Bearer
      credentials: <value of METRICS_TOKEN from .env>
```

Available series: `swift_vapor_scans`, `swift_vapor_scans_by_status{status="..."}`,
`swift_vapor_scans_last_24h`, `swift_vapor_users`, `swift_vapor_results`,
`swift_vapor_scheduled_scans_active`, `swift_vapor_plugin_cache_rows`,
`swift_vapor_plugin_cache_hits_total`, `swift_vapor_plugin_cache_misses_total`,
`swift_vapor_notifications_sent_total{channel="..."}`,
`swift_vapor_backup_last_success_unixtime`, `swift_vapor_backup_age_seconds`
and `swift_vapor_backup_fresh`. Starter availability and backup alerts live in
`ops/prometheus/swift-vapor-alerts.yml`; validate and load them through the
Prometheus rule-file mechanism used by your monitoring installation.

If `METRICS_TOKEN` is unset, the endpoint falls back to requiring an admin
session cookie (legacy behaviour).

---

*Built with Swift + Vapor · Deployed on a hardened Ubuntu VPS · Protected by Cloudflare*
