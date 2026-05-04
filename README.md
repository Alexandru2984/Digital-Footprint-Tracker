# Digital Footprint Tracker

> **Live demo:** [https://swift.micutu.com](https://swift.micutu.com)

A production-grade **OSINT aggregation engine** built with **Swift + Vapor** on a hardened Linux VPS. Scans an email address, username, domain, or phone number across 500+ sources in parallel, streams results live via SSE, and visualises them as an interactive force-directed identity graph.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Swift 6 + Vapor 4 |
| Database | PostgreSQL (Fluent ORM) |
| Frontend | Vanilla JS + Tailwind CSS + D3.js v7 |
| Reverse proxy | nginx (rate limiting, security headers, CSP) |
| Deployment | systemd service on Ubuntu VPS |
| Network | Cloudflare DNS + proxy (DDoS shield, TLS) |
| Tests | XCTest (13 tests, all passing) |

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
  │  /api/*  →  strip prefix  →  Vapor :8082
  │  /*       →  static files (frontend/)
  ▼
Vapor 4 (async/await, Swift concurrency)
  ├── ScanController   — POST /scan, GET /results/:id, GET /stream/:id (SSE)
  ├── StatsController  — GET /stats
  └── Plugin Pipeline  — parallel TaskGroup, 120s timeout
        ├── GravatarPlugin          (email)
        ├── HaveIBeenPwnedPlugin    (email — breach data)
        ├── PastebinPlugin          (email → HIBP paste API / username → pastebin.com)
        ├── BulkEmailPlugin         (email — holehe CLI: 400+ sites)
        ├── UsernamePlugin          (username — GitHub, npm, PyPI, Crates.io, Docker Hub)
        ├── RedditPlugin            (username)
        ├── TwitterPlugin           (username — public CDN endpoint, no key needed)
        ├── PhonePlugin             (phone — AbstractAPI validation)
        ├── DomainPlugin            (domain/IP — dig A/MX/TXT/PTR + whois)
        └── BulkUsernamePlugin      (username — Sherlock data: 478 sites)
  │
  ▼
PostgreSQL
  ├── scans   (id, input, status, created_at, completed_at)
  └── results (id, scan_id, source, type, confidence_score, raw_data)
```

---

## Features

### OSINT Engine
- **500+ sources** checked per scan (478 Sherlock sites + 10 dedicated plugins)
- **Email OSINT**: Gravatar, HaveIBeenPwned breaches + pastes, holehe (400+ sites), Pastebin
- **Username OSINT**: GitHub, npm, PyPI, Docker Hub, Crates.io, Reddit, Twitter/X, Pastebin, 478 Sherlock sites
- **Domain / IP OSINT**: DNS A/MX/TXT/SPF records, reverse PTR, WHOIS registrar + expiry
- **Phone OSINT**: E.164 format detection, carrier + country lookup via AbstractAPI
- **Parallel execution**: all plugins run concurrently in a Swift `TaskGroup` with a 120s hard timeout

### Real-time Streaming
- **Server-Sent Events (SSE)**: results appear live as each plugin finishes
- Automatic fallback to 3-second polling if SSE unavailable
- Live confidence filter (toggle ≥70% confidence)

### Frontend
- **Stats Dashboard**: total scans, last 24h/7d activity, top sources bar chart
- **Identity Graph**: D3.js v7 force-directed graph — centre node = target, leaf nodes = found sources, edge colour = confidence
- Scan history (localStorage, last 20 scans)
- JSON export, PDF via browser print (`@media print` CSS)
- Share link (UUID-based, copyable)
- Force rescan (bypass 7-day cache)
- Input type auto-detection: EMAIL / USERNAME / DOMAIN / PHONE badge

### Security
- **CSP** with inline script hash (`sha256-…`), `'self'`-only sources
- `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
- `X-Robots-Tag: noindex, nofollow`
- nginx rate limiting: 10 req/s on `/scan`, 30 req/s on all API routes
- Input sanitisation: character whitelist + 255-char limit before any plugin runs
- `rawData` capped at 8 KB, `source`/`type` at 64 chars, `confidenceScore` clamped `[0.0, 1.0]`
- SSE connection limit (30 concurrent) via `NIOAtomic` counter
- All plugins use `URLSession` (Foundation) — safe from Vapor lifecycle races
- Holehe subprocess bounded by 60s kill timer via `DispatchSemaphore`
- PII masked in audit logs: `***@domain.com`, `use***`

---

## API Reference

### `POST /api/scan`
Start a new scan (or return a recent cached result).

```json
{ "input": "target@example.com", "force": false }
```

Returns `{ "scanID": "uuid", "status": "pending", ... }`

### `GET /api/stream/:id`
SSE stream — emits individual `PluginResult` objects as `message` events, then a `done` event.

### `GET /api/results/:id`
Fetch full scan result (polling endpoint).

### `GET /api/stats`
Platform statistics.

```json
{
  "totalScans": 42,
  "scansLast24h": 5,
  "scansLast7d": 17,
  "totalResults": 1240,
  "topSources": [{ "source": "GitHubAccountCheck", "hitCount": 38 }, ...],
  "recentTargets": ["***@gmail.com", "use***", ...]
}
```

---

## Local Setup

### Prerequisites
- Swift 5.10+
- PostgreSQL
- Python 3 + [holehe](https://github.com/megadose/holehe) (`pip install holehe`)

### 1. Clone & configure

```bash
git clone https://github.com/Alexandru2984/Digital-Footprint-Tracker
cd Digital-Footprint-Tracker
cp .env.example .env   # edit with your DB credentials
```

**.env**
```
PORT=8082
DATABASE_HOST=localhost
DATABASE_USERNAME=footprint_user
DATABASE_PASSWORD=your_password
DATABASE_NAME=footprint_db
HOLEHE_PATH=/usr/local/bin/holehe
HOLEHE_PYTHONPATH=/path/to/site-packages
# Optional:
HIBP_API_KEY=your_hibp_key
ABSTRACT_PHONE_API_KEY=your_abstract_key
```

### 2. Build & run

```bash
swift build -c release
swift run Run migrate      # run DB migrations
swift run Run serve        # starts on PORT from .env
```

### 3. Tests

```bash
swift test --enable-xctest
```

---

## Project Structure

```
Sources/App/
├── Controllers/
│   ├── ScanController.swift   — scan, results, SSE stream
│   └── StatsController.swift  — /stats endpoint
├── Models/
│   ├── Scan.swift
│   └── Result.swift
├── Plugins/
│   ├── BulkEmailPlugin.swift
│   ├── BulkUsernamePlugin.swift
│   ├── DomainPlugin.swift
│   ├── GravatarPlugin.swift
│   ├── HaveIBeenPwnedPlugin.swift
│   ├── PastebinPlugin.swift
│   ├── PhonePlugin.swift
│   ├── RedditPlugin.swift
│   ├── TwitterPlugin.swift
│   ├── UsernamePlugin.swift
│   └── sherlock_data.json     — 478 Sherlock site definitions
├── Services/
│   ├── NoCacheMiddleware.swift
│   └── ScanRateLimiter.swift
├── Migrations/
├── configure.swift
└── routes.swift
frontend/
├── index.html                 — single-page app
├── d3.min.js                  — D3.js v7 (local, no CDN)
└── tailwind.css               — compiled Tailwind (SRI hash in HTML)
Tests/AppTests/AppTests.swift  — 13 XCTests
```

---

## Adding a New Plugin

1. Create `Sources/App/Plugins/YourPlugin.swift`

```swift
struct YourPlugin: FootprintPlugin {
    let name = "YourSource"

    func scan(input: String, on app: Application) async throws -> [PluginResult] {
        // return [] to skip, or [PluginResult(...)] for a hit
    }
}
```

2. Add to the `plugins` array in `ScanController.swift`:

```swift
let plugins: [any FootprintPlugin] = [
    // ... existing plugins
    YourPlugin()
]
```

Plugins run concurrently — no further wiring required.

---

## Deployment (production)

```bash
swift build -c release
sudo systemctl restart vapor-footprint
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

## Endpoints

- `POST /scan`: Start a new scan (`{"input": "username_or_email"}`).
- `GET /results/:id`: Retrieve results by scan UUID.

## Local Setup

### Development vs Production

**Development:**
1. Install Swift and PostgreSQL.
2. Run `swift build`.
3. Set environment variables.
4. Run `.build/debug/Run serve`.
5. Access backend at `http://localhost:8080`.
6. Open `frontend/index.html` locally in a browser, keeping in mind the URLs points to `/api`. Alternatively, configure a local reverse proxy or CORS in Vapor.

**Production:**
Served securely via NGINX with SSL. The backend runs as a `systemd` service (`vapor-footprint.service`) and NGINX acts as a reverse proxy for API requests and serves the frontend static files.
