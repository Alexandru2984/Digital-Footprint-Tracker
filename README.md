# Digital Footprint Tracker

A modular Swift/Vapor application to track digital footprints based on email or username.

## Architecture

- **Swift + Vapor**
- **PostgreSQL + Fluent**
- **Modular Plugins:** Easy to extend.

## Endpoints

- `POST /scan`: Start a new scan (`{"input": "username_or_email"}`).
- `GET /results/:id`: Retrieve results by scan UUID.

## Local Setup

1. Install Swift and PostgreSQL.
2. Run `swift build`.
3. Set environment variables (or rely on defaults).
4. Run `.build/debug/Run serve`.
