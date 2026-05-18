# Digital Footprint Tracker

[![CI](https://github.com/Alexandru2984/Digital-Footprint-Tracker/actions/workflows/ci.yml/badge.svg)](https://github.com/Alexandru2984/Digital-Footprint-Tracker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Swift](https://img.shields.io/badge/swift-6.0-orange.svg)](https://swift.org)
[![Live Demo](https://img.shields.io/badge/demo-swift.micutu.com-success.svg)](https://swift.micutu.com)

A production-grade **OSINT aggregation engine** built with **Swift + Vapor** on a hardened Linux VPS. Scans an email address, username, domain, IP, or phone number across 500+ sources in parallel, streams results live via SSE, and visualises them as an interactive force-directed identity graph. Ships with full authentication, an admin panel, API keys, scheduled scans, webhooks, multi-channel notifications, shareable reports, and an audit log.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Swift 6 + Vapor 4 (async/await, `TaskGroup` concurrency) |
| Database | PostgreSQL (Fluent ORM, 18 migrations) |
| Frontend | Vanilla JS + Tailwind CSS + D3.js v7 |
| Reverse proxy | nginx (rate limiting, security headers, CSP) |
| Deployment | systemd (`swift-vapor.service`) on Ubuntu VPS |
| Network | Cloudflare DNS + proxy (DDoS shield, TLS) |
| Email | Raw SMTP (Mailcow / SendGrid compatible) |
| Tests | XCTest (27 tests, all passing) |

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
- Bearer auth via `Authorization: Bearer <key>` — equivalent to a logged-in session for that user
- Issue / revoke endpoints under `/api/api-keys`

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
- `rawData` capped at 8 KB, `source`/`type` at 64 chars, `confidenceScore` clamped `[0.0, 1.0]`
- All plugins use `URLSession` (Foundation) — safe from Vapor lifecycle races
- Holehe subprocess bounded by a 60 s kill timer via `DispatchSemaphore`
- PII masked in audit logs: `***@domain.com`, `use***`
- **API keys & share-report tokens stored hashed**, never in plaintext
- `TokenEncryption` service (AES-GCM) for sensitive at-rest secrets
- SMTP header-injection guard (CRLF stripped from `From` / `To` / `Subject`)
- Per-user `retention_days` + daily `ScanCleanupLifecycle` (default 30 d)

---

## API Reference

Full OpenAPI spec is served at **`/openapi.yaml`** and rendered in-app.

### Core
- `POST /api/scan` — start scan or return cached result. `{ "input": "...", "force": false }`
- `GET  /api/stream/:id` — SSE stream of `PluginResult` events
- `GET  /api/results/:id` — full scan result
- `GET  /api/stats` — aggregate stats

### Auth
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET  /api/auth/me`

### User
- `GET /api/my-scans` — last 50 scans for the authenticated user (input masked)
- `GET /api/admin/scans` — last 100 scans across all users (admin only)

### Other route groups
`/api/api-keys`, `/api/scheduled-scans`, `/api/bulk-scan`, `/api/share`, `/api/diff`,
`/api/correlate`, `/api/tags`, `/api/notifications`, `/api/export`, `/api/report/:id`, `/api/health`

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

### Option B: Native build

#### Prerequisites
- Swift 6 toolchain
- PostgreSQL
- Python 3 + [holehe](https://github.com/megadose/holehe) (`pip install holehe`)

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
HOLEHE_PATH=/usr/local/bin/holehe
HOLEHE_PYTHONPATH=/path/to/site-packages
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

```bash
swift build -c release
sudo systemctl restart swift-vapor
sudo nginx -t && sudo systemctl reload nginx
```

After any change to the inline `<script>` block in `frontend/index.html`, recompute the CSP hash:

```bash
python3 -c "
import hashlib, base64, re
s = re.findall(r'<script>(.*?)</script>', open('frontend/index.html').read(), re.DOTALL)[0]
print('sha256-' + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode())
"
```

Then update the `Content-Security-Policy` header in `/etc/nginx/sites-available/swift.micutu.com`.

---

*Built with Swift + Vapor · Deployed on a hardened Ubuntu VPS · Protected by Cloudflare*
