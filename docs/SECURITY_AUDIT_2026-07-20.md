# Extreme security audit — 2026-07-20

## Executive summary

This review covered the Swift/Vapor backend, browser frontend, PostgreSQL
schema and migrations, subprocesses, outbound network clients, Docker and CI
supply chain, nginx/Cloudflare/Tor ingress, systemd confinement, backup path,
SSH deployment boundary, and selected live-VPS state.

The repository is materially safer after this pass, but **the live service is
not yet running these changes**. The production binary and `/etc` configuration
remain on the previous release. Do not describe the prepared fixes as deployed
until the rollout checklist below has completed.

The highest live risks are operational trust-boundary failures:

1. The application and the personal/admin account both use Unix user `micu`.
   That account has `NOPASSWD: ALL`. The currently deployed service sandbox
   has `ProtectHome=read-only`, so it does not hide the user's SSH material.
2. Two automation-labelled SSH keys are unrestricted. Only the
   `swift-vapor-deploy@github-actions` key has a forced command and SSH
   forwarding/PTY restrictions.
3. The Cloudflare-proxied origin still accepts direct HTTPS connections to the
   public VPS address when the Host/SNI is supplied, bypassing Cloudflare WAF,
   bot controls and edge rate limits.
4. The backup script in the worktree now fails closed without an encrypted
   credential, while the live timer/unit has not yet been migrated to provide
   that credential. Provision the credential and unit before the next timer.

No private-key material or real `.env` file is tracked in the current Git tree
or its reachable history. Secret values were not printed during this audit.

## Scope and method

Reviewed surface:

- 146 Swift source files / roughly 13.1k Swift LOC;
- 20 controllers, 32 plugin implementations and 176 route declarations/calls;
- 33 registered migrations and three lifecycle handlers;
- 7.5k frontend HTML/JS/CSS LOC;
- nginx clearnet and onion vhosts, Cloudflare trust ranges and CSP generation;
- systemd application and backup services;
- CI SSH deployment path, Dockerfile, Compose topology and dependency locks;
- live listeners, firewall posture, process identity, file modes, timers,
  production HTTP behavior and read-only database counts.

Validation performed:

- `swift test` under the pinned Swift 6.2 container: **128/128 passed**;
- clean static release compilation under Swift 6.2;
- production image smoke test as UID 10001, including Python imports and
  `holehe --help`;
- Dockerfile build checks and `docker compose config --quiet`;
- hash-locked Python runtime install in an isolated venv and PDF generation;
- backup stream encryption plus authenticated decrypt/decompress verification
  against the real database, using temporary output only;
- nginx/systemd configuration generation and offline validation;
- `npm audit`: no known frontend dependency findings at review time;
- inspection of resolved Swift dependency revisions against the relevant
  SwiftNIO-family advisories.

Not performed:

- no destructive exploitation, credential guessing, traffic flood, mail or
  webhook delivery to third parties;
- no production restart, database migration, `/etc` change, firewall change,
  Cloudflare dashboard change, Git push or GitHub Environment change;
- no intrusive audit of unrelated applications sharing the VPS.

## Findings register

Status meanings:

- **Prepared** — remediation is committed but not active on production.
- **Open** — remediation still requires design, operator action or both.
- **Accepted** — documented residual risk, not silently treated as fixed.

### P0 — critical / rollout blockers

| ID | Finding | Evidence / impact | Status | Required action |
|---|---|---|---|---|
| P0-01 | Personal, runtime and deploy identity are conflated | `swift-vapor.service` runs as `micu`; `/etc/sudoers.d/micu-nopasswd` grants `NOPASSWD: ALL`. App RCE can expose personal files and dramatically increases host blast radius. `NoNewPrivileges` helps only while confinement remains intact. | Open | Create non-login `swift-vapor` runtime user and separate `swift-deploy`; move runtime files/secrets outside the personal home; remove broad sudo. |
| P0-02 | Unrestricted automation SSH keys | `github-actions-deploy` and `github-actions-vix-deploy` entries lack forced-command/restrict options. Theft can yield an interactive shell with the rights of `micu`. | Open | Identify consumers out-of-band, replace with per-project keys, forced command, `restrict`, source restrictions where stable, then revoke old keys. |
| P0-03 | Backup migration is incomplete | The new worktree script requires an encrypted credential, but the live unit still invokes it without `LoadCredentialEncrypted`. The next run will fail safely rather than write plaintext. | Prepared / urgent | Provision the systemd encrypted credential, install the committed unit/timer, run and restore-test one encrypted backup before the next timer. |
| P0-04 | Prepared application fixes are not deployed | Production still executes the previous release binary. All application-level fixes in this report therefore remain absent live. | Prepared | Controlled rollout only after a verified backup, toolchain/runtime preflight and migration review. |

### P1 — high

| ID | Finding | Evidence / impact | Status | Required action |
|---|---|---|---|---|
| P1-01 | Direct-to-origin Cloudflare bypass | Direct TLS request to the VPS origin returned 200 with the public host name. Attackers can bypass Cloudflare controls and use a different perceived client identity/rate-limit path. | Prepared | Install generated Cloudflare peer map and guarded TLS vhost; validate Cloudflare path remains 200 and direct origin becomes 403. Prefer Authenticated Origin Pulls/mTLS as the next layer. |
| P1-02 | Existing systemd sandbox exposes too much home state | Live drop-in uses `ProtectHome=read-only`; same-UID application can read personal SSH/config files. Live security score was 5.2 MEDIUM. | Prepared / partially open | Deploy committed tmpfs-home/device/capability/network sandbox immediately; then complete P0-01 dedicated-user migration. Prepared offline score: 2.8 OK. |
| P1-03 | Plaintext, single-host backups | Seven mode-0600 gzip SQL dumps exist locally, with no offsite copy or demonstrated disaster restore. Root/host compromise can take app and backup together. | Prepared / open | Encrypt new backups, migrate or securely expire legacy dumps, add immutable offsite copy, retention tiers and scheduled restore drills. Never delete the only restorable copy. |
| P1-04 | Deployment is not atomic | Current script fast-forwards the worktree before building. nginx serves frontend files directly from that worktree. Failed build/restart/CSP sync can leave a mixed release. | Open | Build into immutable release directories, run migration preflight, atomically switch `current`, health-check and auto-rollback binary + static assets + CSP as one unit. |
| P1-05 | Production Python runtime is broken and coupled to a user site | Host `holehe` was installed for Python 3.12 while host Python is 3.14; imports fail. Hard-coded paths coupled execution to `/home/micu/.local`. | Prepared | Install committed hash-locked venv, set `HOLEHE_PATH` and `REPORT_PYTHON_PATH`, then smoke-test as the service identity. |
| P1-06 | Secrets share one flat environment and one master encryption key | App compromise exposes DB, SMTP and vendor tokens plus the data-encryption key. A single AES-GCM master has no online rotation generation. | Open | Split credentials by capability, use systemd credentials or a secret manager, implement versioned KEK/DEK rotation and a tested re-encryption job. |
| P1-07 | Startup migrations and deploy rollback are coupled | Schema migration occurs during application startup. A failed deploy may apply forward-only schema changes before binary rollback. | Open | Move migrations to an explicit, backed-up, advisory-locked deployment step; classify expand/migrate/contract changes and provide compatible rollback windows. |

### P2 — medium

| ID | Finding | Evidence / impact | Status | Required action |
|---|---|---|---|---|
| P2-01 | Rate limits and workload admission are process-local | Restart clears counters and future horizontal replicas multiply limits. | Accepted / planned | Redis-backed token buckets, global concurrency leases and per-provider budgets. |
| P2-02 | Scheduled and watched work is not a durable queue | Lifecycle runners live inside the web process. Restarts can delay work; replicas could duplicate execution. | Open | Durable jobs with leases, idempotency keys, retry policy, dead-letter queue and worker role separation. |
| P2-03 | Audit log is mutable and co-resident | A DB admin or application compromise can alter the evidence trail. | Open | Append-only DB role plus signed hash chain and remote/WORM export. |
| P2-04 | Observability is incomplete | `/metrics` is protected but no production metrics credential/scrape/alert path was confirmed. Security events are not centrally alerted. | Open | Provision scoped metrics auth, dashboards and alerts for auth abuse, queue saturation, backup failure, origin bypass and unusual egress. |
| P2-05 | CSP deployment is fragile | Multiple large inline scripts require exact generated hashes; static files change before current deploy updates nginx. `style-src 'unsafe-inline'` remains. | Open | Move inline JS/styles to versioned external assets, adopt static strict CSP, CSP reporting and asset integrity tests. |
| P2-06 | Container build is not fully reproducible | Base/frontend actions and Python artifacts are pinned, but Ubuntu apt package versions/repositories are time-varying. No image vulnerability gate, SBOM or signature exists. | Partially prepared | Snapshot apt repository or pin packages, scan image, generate CycloneDX/SPDX SBOM, sign image and verify provenance at deploy. |
| P2-07 | Swift 6 language-mode debt | Swift 6.2 compiler succeeds in Swift 5 mode but emits mutable `Sendable`, async API and deprecated API warnings that become errors in Swift 6 mode. | Open | Migrate in bounded modules, enable strict-concurrency warnings as CI signal, then switch language mode. |
| P2-08 | Origin allowlist needs lifecycle automation | Cloudflare CIDRs are correct at audit time, but no installed refresh/check timer is represented. Stale ranges can cause outage or weaken assumptions. | Open | Add timer that checks official lists, validates config, reloads safely and alerts on failure/change. |
| P2-09 | Host exposes unrelated public services | UFW and listeners show several non-80/443 services outside this repository. A compromise elsewhere can become a same-host pivot. | Out of repo scope | Inventory owners, bind private services to VPN/loopback, segment hosts or containers, and remove abandoned listeners. |
| P2-10 | CI quality gates are incomplete | CI pins actions and host trust, but lacks secret scanning, SAST, dependency policy, container scanning and protected-branch evidence. | Partially prepared | Add gitleaks, Semgrep/CodeQL where supported, OSV/Dependabot, image scan, SBOM/signing and required checks. |

### P3 — low / defense in depth

| ID | Finding | Status / action |
|---|---|---|
| P3-01 | `/health` is public and reaches the database | Keep response minimal; use a cheap liveness route and an internal readiness route. |
| P3-02 | Free `ip-api.com` transport is HTTP | Replace with an HTTPS provider or disable geolocation; never attach unrelated PII/secrets. |
| P3-03 | Dependency manifests remain mutable at update time | Add scheduled update PRs, changelog review and advisory SLA; retain exact `Package.resolved`. |
| P3-04 | No formal abuse/legal workflow for an OSINT product | Add acceptable-use consent, abuse desk, takedown workflow, target-policy controls and immutable acceptance records. |
| P3-05 | No proven multi-tenant authorization property suite | Add generated/fuzzed route matrix that asserts tenant isolation for every ID/token/state combination. |

## Remediations committed in this pass

Each logical stage has one neutral commit with the repository's existing author
identity and no attribution/co-author trailers:

| Commit | Stage |
|---|---|
| `a32b742` | lock and update Swift dependencies |
| `93228da` | require encrypted sensitive storage and key continuity |
| `37b90c8` | bound scan workload amplification |
| `217e18e` | scope and expire API keys |
| `1a628b8` | rotate and bound privileged sessions |
| `897db34` | enforce session request provenance |
| `c8cb00a` | keep geolocation private and redact webhooks |
| `725283d` | bound and validate outbound HTTP |
| `76a5181` | align application/nginx body limits |
| `5caead9` | hash, expire and quota shared report links |
| `69ea5c7` | redact operational telemetry |
| `4768c15` | isolate and bound subprocesses |
| `07c8ccb` | make account erasure transactional |
| `4c9e6a2` | bound metadata and notification lifecycle |
| `669a856` | require Cloudflare peers at the TLS origin |
| `c798cbf` | strengthen systemd confinement |
| `fc14f9c` | encrypt and verify database backups |
| `2d74897` | pin and authenticate CI supply chain |
| `862a12b` | isolate and hash-lock runtime dependencies |

Important implementation properties:

- sensitive database fields use versioned AES-256-GCM envelopes and production
  startup fails closed without the correct key;
- tokens are one-time values stored as hashes; API keys have explicit scopes
  and expiry, and sensitive controls require recent session authentication;
- outbound user-controlled HTTP resolves and validates every redirect hop,
  rejects private/special networks and enforces response/time limits;
- subprocesses have exact executable paths, minimal environments, private temp
  homes, bounded stdin/stdout/stderr, deadlines and forced termination;
- account deletion is transactional; notifications/tags/share links/cache and
  metadata have ownership, quota and lifecycle bounds;
- the container runs read-only/capability-free as UID 10001, has loopback-only
  published ingress, isolates Postgres on an internal network and installs
  Python packages only from a hash lock;
- CI actions, images and SSH host identity are pinned/verified instead of using
  mutable tags or trust-on-first-use discovery.

## Controlled production rollout

This ordering is mandatory because it keeps a recoverable database and avoids
deploying code whose native/Python prerequisites are absent.

1. **Freeze and identify**
   - Record current Git SHA, binary checksum, unit/vhost checksums and DB schema.
   - Identify the owners of both unrestricted automation SSH keys.
   - Confirm an out-of-band root session remains available throughout rollout.
2. **Restore capability first**
   - Provision the encrypted backup credential and committed backup unit.
   - Produce one encrypted dump, copy it off-host and restore it into an
     isolated PostgreSQL instance; compare row counts and key tables.
3. **Runtime preflight**
   - Install Swift 6.2 for native builds or select the tested container path.
   - Install the hash-locked Python venv and test PDF + holehe under the exact
     service identity and sandbox.
   - Ensure `ENCRYPTION_KEY` is securely backed up; replacing it loses access
     to encrypted fields.
4. **Identity and secrets boundary**
   - Create non-login `swift-vapor`; migrate environment/venv/runtime paths;
     make releases root/deploy-owned and read-only to the app.
   - Create separate `swift-deploy` with only the audited forced command.
   - Remove `micu NOPASSWD: ALL`; keep only narrowly enumerated operations.
5. **Application and migrations**
   - Stop background scheduler/watch execution or take a brief maintenance
     window; run migration preflight after the verified backup.
   - Deploy the tested release, run readiness and authenticated smoke tests,
     verify scheduler leases and inspect errors before restoring traffic.
6. **Ingress**
   - Install generated Cloudflare real-IP/origin maps and vhosts; `nginx -t`.
   - Verify through Cloudflare, direct IPv4/IPv6 origin, onion service, body
     limits, SSE timeouts, security headers and real client IP semantics.
7. **Credential/key cleanup**
   - Revoke obsolete unrestricted SSH keys and rotate every automation key
     whose provenance is uncertain.
   - Rotate vendor/SMTP/session/metrics credentials after the Unix boundary is
     corrected; rotate the data-encryption key only with a migration plan.
8. **Observe and close**
   - Watch logs/metrics, backup alerting, DB locks/latency and outbound failure
     rate for at least one scheduler cycle.
   - Record the deployed SHA and evidence. Only then mark Prepared findings as
     deployed/verified.

## Release acceptance gates

A production release fails closed unless all of these are true:

- 128 tests pass under the pinned Swift 6.2 toolchain;
- release build and runtime smoke tests pass;
- dependency/secret/SAST/image scans meet the agreed severity policy;
- a recent encrypted backup has a successful isolated restore result;
- migrations are reviewed as expand/contract compatible or have a maintenance
  and recovery procedure;
- origin guard, nginx and systemd configs validate before reload;
- deployment can atomically revert app + frontend + CSP to the previous SHA;
- post-deploy health, authenticated authorization, report generation, one
  bounded scan and scheduler state are verified.

## Residual-risk statement

Even after rollout, this is an OSINT service that deliberately makes extensive
network requests to changing third parties. External APIs, recovery-flow tools
and target-controlled hosts are untrusted. The correct long-term architecture
is a small web control plane plus isolated, quota-controlled workers with
explicit egress policy, durable jobs and no access to control-plane secrets.
