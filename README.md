# Digital Footprint Tracker

A modular Swift/Vapor application to track digital footprints based on email or username.

## Architecture

- **Swift + Vapor**
- **PostgreSQL + Fluent**
- **Modular Plugins:** Easy to extend.

## Frontend Overview

The dashboard is built with Vanilla JavaScript and styled using TailwindCSS (via CDN). It provides a modern, responsive, hacker/OSINT style interface to initiate scans and display the aggregated digital footprint results dynamically.

### Screenshots Placeholder

*(Insert screenshots of the dashboard and scan results here)*

## How to Access UI

The frontend dashboard is accessible via:
**URL:** [https://swift.micutu.com](https://swift.micutu.com)

## How Frontend Connects to Backend

The frontend communicates with the backend asynchronously using the native `fetch` API:
1. **Initiate Scan:** Sends a `POST` request to `/api/scan` with the target username or email.
2. **Poll Results:** Automatically polls `/api/results/:id` every 2 seconds until the scan results are fully available.
3. **NGINX Proxy:** NGINX handles traffic routing. Root (`/`) serves the static frontend files, while the `/api/` prefix is reverse-proxied to the Vapor backend.

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
