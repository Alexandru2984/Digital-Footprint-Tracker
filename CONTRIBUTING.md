# Contributing

Thanks for your interest in improving Digital Footprint Tracker. This document
covers everything you need to spin up a development environment, run the test
suite, follow the style conventions, and submit a pull request that has a high
chance of landing.

---

## Quick start

The fastest path is the Docker setup — it provisions PostgreSQL + the app in
two commands and needs nothing else on your host:

```bash
cp .env.docker.example .env       # then edit *_PASSWORD + ENCRYPTION_KEY
docker compose up -d --build
open http://localhost:8085
```

If you prefer a native build, see the prerequisites below.

---

## Native development setup

### Prerequisites

| Tool         | Version  | Notes                                                |
|--------------|----------|------------------------------------------------------|
| Swift        | 6.0+     | Verify with `swift --version`                        |
| PostgreSQL   | 14+      | Local instance; tests use in-memory SQLite           |
| Python       | 3.10+    | Required by the `BulkEmail` (holehe) plugin          |
| `holehe`     | latest   | `pip install holehe`                                 |
| `curl`       | any      | EmailService shells out to it for SMTPS              |

### Clone & configure

```bash
git clone https://github.com/Alexandru2984/Digital-Footprint-Tracker
cd Digital-Footprint-Tracker
cp .env.example .env             # then edit values
```

Minimal `.env`:

```
PORT=8085
DATABASE_HOST=localhost
DATABASE_USERNAME=footprint_user
DATABASE_PASSWORD=your_password
DATABASE_NAME=footprint_db
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=your_strong_password
ENCRYPTION_KEY=<64 hex chars; generate with `openssl rand -hex 32`>
```

### Run

```bash
swift build -c release
swift run Run serve              # migrations apply on startup
```

The first run seeds the admin user from `ADMIN_USERNAME` / `ADMIN_PASSWORD`.

---

## Running tests

```bash
swift test --enable-test-discovery
```

The test suite is hermetic — it boots an in-memory SQLite for each test and
tears down on completion. No `.env`, no PostgreSQL, no network calls. CI runs
the same command on every push and PR (`.github/workflows/ci.yml`).

If you add a model or a migration, register it in the test setup too
(`Tests/AppTests/AppTests.swift` → `makeApp()`).

---

## Code style

We use [SwiftLint](https://github.com/realm/SwiftLint). Configuration lives in
`.swiftlint.yml`; most rules are at `warning` severity (annotations on PRs)
rather than `error` (blocks merge).

Run locally if you have `swiftlint` installed:

```bash
swiftlint lint
```

If you don't, CI will surface lint issues on your PR.

### General conventions

- **No silent failures.** Wrap network / IO in `do/catch` and log via
  `req.logger` or `app.logger`. The notification dispatcher is the only place
  where best-effort fire-and-forget is acceptable.
- **No hard-coded secrets.** Anything sensitive reads from `Environment.get`
  with an explicit fallback or a fail-closed `throw`.
- **Plugins are `Sendable`.** Plugin types must be value types or `final`
  classes; the runner shares them across the cooperative pool.
- **Migrations are dialect-aware.** Tests run on SQLite, production on
  PostgreSQL. See `AddScanStatus.swift` for the pattern: pure-Fluent schema
  changes work everywhere, raw SQL fall-backs go inside a `do { ... } catch {}`
  block to silently skip on engines that don't support them.

---

## Adding a new OSINT plugin

1. Create `Sources/App/Plugins/<Name>Plugin.swift` conforming to
   `FootprintPlugin`:

   ```swift
   struct GitHubPlugin: FootprintPlugin {
       let name = "GitHub"
       func scan(input: String, on app: Application) async throws -> [PluginResult] {
           // Validate input shape (only run for usernames, not emails / IPs).
           // Hit the upstream with URLSession, parse, return PluginResult rows.
       }
   }
   ```

2. Register it in `ScanController.defaultPlugins` (and in any per-input-type
   plugin list inside `routes.swift` / `ScanController` if you want it to run
   for `/scan/bulk` too).

3. Add a TTL for the new plugin in `PluginCacheStore.ttls` so its cache entry
   age matches how often the upstream data actually changes (see existing
   entries for guidance).

4. If the plugin needs an API key, source it from `Environment.get` and skip
   silently (return `[]`) when the key is missing — never crash startup.

5. Add an integration test to `Tests/AppTests/AppTests.swift` if the plugin
   has parseable output structure or input-normalisation behaviour worth
   regression-testing.

---

## Submitting a pull request

1. **One concern per PR.** Refactor + feature + bug-fix in one PR is hard to
   review; smaller PRs land faster.
2. **Conventional-style commit subject** (`feat:`, `fix:`, `docs:`, `refactor:`,
   `test:`, `chore:` — see `git log --oneline` for examples).
3. **Tests for new behaviour.** Anything that changes auth, authorization, or
   input validation MUST have a test covering both the happy path and a
   rejection path.
4. **No surprises in the diff.** Stick to the scope described in the PR body;
   if you spotted something else worth fixing, mention it and either split it
   off or call it out explicitly.

CI must pass before review. A SwiftLint annotation on your PR isn't blocking,
but please address it (or argue for the rule to be disabled) rather than
leaving it for someone else.

---

## Security disclosures

See [`SECURITY.md`](SECURITY.md). Do **not** open a public issue for a
suspected vulnerability — email the address listed there instead.
