# Product and security roadmap

This roadmap deliberately puts containment, recoverability and abuse controls
before feature volume. Priorities are ordered; items within a phase can run in
parallel only when their dependencies are satisfied.

## Current checkpoint — 2026-08-30

Every claim below was checked against the running box, not inferred from the
repository. Repository test success is still not production acceptance evidence;
what follows is the production evidence.

- **Release provenance.** Production serves commit `5faa530` from
  `/srv/swift-vapor/releases/<sha>` through the immutable `current` symlink. The
  release was built and deployed by CI, and the deployed SHA equals the accepted
  artifact.
- **Identity separation.** `swift-vapor` (uid 977, `nologin`), `swift-deploy`
  (976) and `swift-backup` (975, `nologin`) exist, with `swift-backup-check` as
  the read-only backup verification group. The service has no personal-home
  access.
- **Secrets.** Six encrypted systemd credentials under
  `/etc/credstore.encrypted`; `/etc/swift-vapor/app.env` is non-secret
  configuration only.
- **Recoverability.** The daily backup timer is active and retains seven
  authenticated, gzip-verified artifacts. An isolated restore drill produced
  evidence at
  `/var/lib/swift-vapor-recovery/restore-drills/restore-2026-08-24T12-59-29Z.json`.
- **Migration gate.** The web unit forces `AUTO_MIGRATE=false`; migrations apply
  only through `swift-vapor-migrate.service`.
- **Operator alerting** (delivered 2026-08-30). `OnFailure=` on the application,
  backup and probe units routes to `swift-vapor-alert@`, and a 15-minute probe
  covers readiness, restart flapping under `Restart=always`, backup staleness,
  certificate expiry and disk headroom. Delivery and the failure chain were
  verified end to end on the box, not just installed.

### Accepted deviations

These are decisions, not gaps. They override the exit criteria they contradict.

- **`micu` keeps broad `NOPASSWD: ALL` sudo.** The operator configured this
  deliberately as the independent root-recovery path on a shared, multi-tenant
  box. It supersedes the "broad sudo removed" exit criterion below. Deploy
  automation is unaffected: it still authenticates with the restricted
  forced-command key.

### Remaining open

- **Metric history.** `/metrics` is exposed and authenticated, but nothing
  scrapes it. The box already runs Prometheus, Alertmanager and node-exporter in
  Docker (`cinetrack-monitoring`), and its Alertmanager delivers mail — but that
  stack cannot reach swift-vapor, which binds loopback-only by design. On-host
  probing now covers liveness and failure paging; metric history, trend alerting
  and dashboards remain open, and closing that gap means deciding whether to
  weaken the loopback binding or to proxy the endpoint to the container network.
- **Origin closure.** Cloudflare AOP/mTLS is not configured, and the origin
  guard is evidenced on IPv4 only while nginx also listens on `[::]:443`.
- **Configuration provenance.** No recorded checksum manifest binds the binary,
  frontend and `/etc` to the accepted commit.
- **Isolated worker.** The VoidAccess dark-web worker is prepared and documented
  but not installed (`DARK_WEB_ENABLED=false`). The `After=` reference to its
  unit in `swift-vapor.service` is intentional forward ordering, not rot.
- **Legal surface.** Anonymous scanning of third-party identifiers is open to
  the internet with no published privacy notice, terms or acceptable-use policy.
  For an OSINT tool operated from the EU this is the largest non-technical gap.

**CISO verdict:** Phase 0 exit criteria are met apart from the explicitly
accepted sudo deviation. Residual risk is concentrated in origin closure
(AOP/IPv6), configuration provenance, absent metric history, and the missing
legal surface — none of which block continued operation, all of which should be
closed before the service is promoted to strangers.

## North-star architecture

```text
Cloudflare + origin authentication
              |
       nginx / API gateway
              |
       Vapor control plane
       /        |         \
 PostgreSQL   Redis      object storage
                 |
          durable job queue
          /       |       \
     light      browser    high-risk
     workers    workers    subprocess workers
          \       |       /
        egress proxy + DNS policy
                 |
          approved external APIs
```

The control plane owns authentication, authorization, billing/quotas and
results. Workers receive short-lived job capabilities, cannot read user/session
secrets, and have per-plugin egress allowlists and resource budgets.

## Phase 0 — production safety

Status as of 2026-08-30, verified against the running box.

| Gate | Production | Evidence |
|---|---|---|
| Restore main SPA/CSP compatibility | **Met** | Exact hashes plus per-request JSD nonce; browser gate open |
| Encrypted backup credential/job | **Met** | Daily timer active, seven verified artifacts, newest authenticated |
| Restore/offsite recovery | **Partly met** | Isolated restore drill evidenced 2026-08-24; off-host immutable copy and measured RPO/RTO still open |
| Dedicated runtime identity | **Met** | `swift-vapor`/`swift-deploy`/`swift-backup`, `/srv` layout, no personal-home access |
| Narrow deploy authority | **Met, with accepted deviation** | Forced-command deploy key only; `micu`'s broad sudo retained deliberately as root recovery |
| Immutable atomic deployment | **Met** | `current` → `releases/<sha>`; deployed SHA equals the CI artifact |
| Explicit migration gate | **Met** | Web unit forces `AUTO_MIGRATE=false`; migrations only via the migrate unit |
| Cloudflare-only origin | **Partly met** | IPv4 enforced; AOP/mTLS absent and IPv6 origin unevidenced |
| Native runtime | **Met** | Swift 6.2 release built and served from the immutable tree |
| Monitoring/paging | **Met for paging, open for metrics** | `OnFailure=` plus a 15-minute probe, delivery verified end to end; nothing scrapes `/metrics` |
| Configuration provenance | **Open** | No checksum manifest binding binary, frontend and `/etc` to the accepted commit |

Phase 0 is closed apart from the rows marked open or partly met above. The
remaining work is tracked in "Remaining open" under the current checkpoint.

## Next atomic delivery stages

Each stage should be one reviewable commit (or a short, explicitly linked
series), with its own rollback note and production evidence before the next one.

1. **Emergency edge consistency — delivered.** The served CSP carries the exact
   hashes plus the per-request JSD nonce; validated and reloaded in production.
2. **Recovery first — delivered except the off-host copy.** Encrypted credential
   provisioned, verified backups running daily, isolated restore drill evidenced,
   and timer failure now pages the operator. An immutable off-host copy and a
   measured RPO/RTO remain open.
3. **Identity cutover — delivered.** `swift-vapor`, `/srv` releases and scoped
   credential access are live and deploy uses a restricted forced-command key.
   Broad sudo for `micu` is retained by operator decision (see accepted
   deviations), not left open by omission.
4. **Atomic release bootstrap — delivered.** Units, nginx and helpers installed,
   explicit migration gate enforced, immutable release selected by symlink, and a
   CI-triggered deploy verified against the accepted SHA.
5. **Origin closure:** deploy peer map/guard, add Cloudflare AOP/mTLS, probe both
   origin address families and alert if direct access ever succeeds.
6. **Crypto envelope v2:** repository implementation delivered: HKDF-separated
   encryption/index keys, AAD binding, key IDs, corruption quarantine, bounded
   previous-key reads, row-locked checkpointed rotation, verification and v1
   rollback. Production rollout/restore evidence remains gated by Phase 0.
7. **Durable execution:** Postgres/Redis queue, idempotency keys, leases,
   cancellation, retry classes, DLQ and separated worker identities/secrets.
8. **Streaming correctness — repository delivered:** durable per-scan cursor,
   zero-gap database allocation across concurrent/old-release writers,
   `Last-Event-ID`, bounded replay, proxy-safe reconnects and the existing
   constant-cost public liveness/internal readiness split. Production rollout
   evidence remains gated by Phase 0.
9. **Truthful delivery — repository core delivered:** encrypted idempotent
   outbox, per-channel leases, typed transient/permanent failures, bounded
   jittered retry, DLQ, audited replay and queue metrics. Production evidence,
   bounce/complaint ingestion and provider-latency dashboards remain gated.
10. **Bounded data plane — export core delivered:** asynchronous paged scan
    exports/reports, encrypted artifacts and completeness manifests, per-user
    quotas, cross-process leases, integrity-checked download expiry and
    cancellation. Correlation jobs and object-storage scale-out remain open.
11. **Security telemetry — signed local ledger delivered:** privacy-minimal
    Ed25519 hash chain, cross-process writer serialization, immutable-event
    triggers, redaction/retention commitments, full verification, metrics and
    alerts. Remote signed checkpoints/stream, auth/egress/admin anomaly alerts,
    drift detection and incident tabletop evidence remain open.
12. **Browser quality gate — repository core delivered:** pinned offline
    Playwright/axe at 320/375/768/1440, WCAG 2.2 AA, overflow/touch targets,
    keyboard focus, reduced motion, DOM-XSS fixtures and CSP execution checks.
    Inline extraction, Trusted Types, manual screen-reader review and the live
    Cloudflare/nginx browser acceptance remain open.
13. **Timeline intelligence pack — repository core delivered:** normalized RDAP,
    certificate-transparency, Wayback and provider join dates; bounded provenance,
    confidence, conflicting-date review and breach recurrence; owner/capability
    API plus responsive DOM-safe UI. Historical DNS/BGP, cross-scan timeline
    diffs and full finding provenance remain open.
14. **Case/team model:** workspaces, RBAC, case tasks/evidence, dual approval,
    property-based tenant isolation and scoped service accounts.
15. **Evidence provenance:** source/version/time/hash/license/freshness on every
    finding, suppression/false-positive lineage and signed export manifests.
16. **Disaster-recovery maturity:** encrypted WAL/PITR, immutable retention tiers,
    quarterly game day and documented RTO/RPO/error-budget decisions.

## Phase 1 — security platform

### Identity and account security

- Passkeys/WebAuthn as the preferred admin and user sign-in method.
- Verified-email activation with expiring, single-use hashed tokens.
- Password reset with single-use tokens, session revocation and notifications.
- Password breach screening using k-anonymity; reject common credentials.
- Device/session inventory with remote logout and “logout everywhere”.
- Step-up authentication for exports, shares, keys, webhooks and admin actions.
- 2FA recovery-code regeneration, encrypted recovery kit and lockout recovery.
- Login anomaly notifications and configurable admin IP/device policy.
- Optional OIDC/SAML for teams; SCIM only after tenant isolation is mature.

### Authorization and tenancy

- Central declarative route-policy table; CI fails on unclassified routes.
  **Delivered in repository:** exact method/path rules are compared to Vapor's
  live registry and unknown runtime paths fail closed.
- Property-based cross-tenant IDOR tests for every model and HTTP method.
  **Core owner-scoped surface delivered:** randomized instances cover 37
  identifier probes, five HTTP methods, 11 collection/export paths, and
  post-request database invariants; future tenant models must extend the gate.
- Organization/workspace model with owner/admin/analyst/viewer roles.
- Resource-level sharing ACLs, expiry, revocation and audit trail.
- Service accounts with narrowly scoped keys and per-key quotas/IP policy.
- Dual approval for destructive admin operations and bulk exports.

### Secrets and cryptography

- Split database, SMTP, metrics and provider credentials by worker capability.
- systemd encrypted credentials with bounded `_FILE` loading are delivered for
  database/encryption/audit secrets; optional provider credentials use reviewed
  drop-ins and `/etc/swift-vapor/app.env` is non-secret configuration only.
- Versioned key-encryption keys and per-record/data-class DEKs (v2 root-derived
  field keys are delivered; external KMS/DEK hierarchy remains future work).
- Online key rotation with progress, verification and rollback checkpoints is
  delivered in-repository; production exercise and evidence remain open.
- Key escrow/recovery procedure with two-person access for production.
- Secret scanning in pre-commit and CI, plus full-history scheduled scan.
  **Repository CI delivered:** every push/PR plus weekly/manual full-history
  Gitleaks scan, exact reviewed fingerprints and scanner positive controls.

### Supply chain and assurance

- Dependabot/Renovate PRs with grouped Swift/Python/frontend updates.
- OSV dependency policy and an SLA for critical/high advisories.
- gitleaks, Semgrep rules, CodeQL where language coverage is useful.
- Trivy/Grype container and OS-package scan with exception expiry.
- CycloneDX and SPDX SBOMs attached to releases.
- Signed images/artifacts, SLSA provenance and deploy-time signature verify.
- Pin apt repository snapshots or package versions for reproducible images.
- Branch protection, required reviews/checks and protected production environment.
- Nightly DAST against a disposable environment; quarterly manual abuse review.

**Repository source gate delivered:** grouped Dependabot coverage spans SwiftPM,
npm, two Python roots, Actions and Docker; pull-request dependency review blocks
new high/critical advisories; pinned Gitleaks and 15 local Semgrep rules have
positive controls; pinned Syft emits validated SPDX/CycloneDX artifacts. Final
image/OS scanning, durable release attachment, signing, SLSA provenance and
deploy-time verification remain open.

### Browser and edge security

- Extract all inline JS/CSS and use a static strict CSP without hash rewriting.
- CSP report-only rollout, collection and alerting before enforcement changes.
- COOP/COEP/CORP evaluation, Trusted Types and DOM-sink linting.
- Cloudflare rate policies by authenticated identity and endpoint cost.
- Turnstile only on abuse-sensitive anonymous flows, with privacy fallback.
- Separate public liveness from internal/database readiness.
- DNSSEC, CAA review, certificate-expiry and unexpected-certificate alerts.

**Repository browser gate delivered:** deterministic Chromium runs without
external network access against the production CSP fixture across four
viewports, enforcing axe WCAG 2.2 AA, focus/keyboard, reduced motion, target
size, overflow and malicious DOM payload controls. Inline script/style
extraction, Trusted Types, manual assistive-technology review, CSP reporting and
live edge evidence remain open.

## Phase 2 — reliable scan engine

### Durable execution

- Redis/Postgres-backed job queue with leases and visibility timeouts.
- Separate API, scheduler and worker processes; no jobs in web lifecycle hooks.
- Idempotency keys on scan/bulk/schedule endpoints.
- Retry taxonomy: transient, provider quota, permanent input, policy rejection.
- Exponential backoff with jitter and per-provider circuit breakers.
- Dead-letter queue with replay after operator review.
- Cancellation propagation from API to HTTP calls and subprocesses.
- Job checkpoints and resumable scans after process/VPS restart.
- Weighted global concurrency and per-user/per-provider budgets.
- Distributed rate limits and scheduler leader election.
- Priority lanes for interactive, scheduled, watch and admin jobs.

### Plugin isolation and quality

- Versioned plugin protocol/SDK with typed input/output schemas.
- Manifest-declared egress domains, secrets, timeout and cost class.
- Workers/containers per risk class with CPU, memory, PID and network quotas.
- Egress proxy that resolves/pins public destinations and logs policy decisions.
- Plugin health score, latency/error history and automatic quarantine.
- Contract fixtures and recorded upstream-response tests.
- Result provenance: plugin/version/request time/evidence URL/hash/expiry.
- Confidence calibration and explanation rather than a single opaque score.
- Provider quota dashboards and cost forecasting.
- Safe staged rollout/canary for plugin updates.

### Scan experience

- Named scan profiles: quick, standard, deep, passive-only and custom.
- Preflight that estimates provider count, duration, quota and privacy impact.
- Live progress by plugin with ETA, cancellation and selective retry.
- Resume/replay failed plugins without duplicating successful findings.
- Saved target lists, deduplication windows and configurable freshness.
- Bulk import from CSV/JSON with validation preview and row-level errors.
- Scan templates and reusable automation recipes.
- Result suppression/false-positive workflow with expiry and reason.
- Data freshness/last-seen/first-seen history per finding.
- Signed webhook events with timestamp, delivery ID and replay protection.

## Phase 3 — investigation and intelligence features

### Entity graph and cases

- Workspaces/cases with members, notes, tasks, status and due dates.
- Merge/split entities with reversible lineage and conflict review.
- Alias, relationship and confidence editing with complete audit history.
- Timeline view across findings, certificates and account/domain events.
  **Repository core delivered:** normalized scan timeline, category filtering,
  bounded provenance/confidence and conflicting-date indicators.
- Timeline source adapters for RDAP/WHOIS domain creation, Wayback first capture,
  certificate-transparency first/last seen, GitHub/GitLab/account join dates,
  breach disclosure dates, DNS history and BGP ownership changes.
- Timeline confidence/provenance, timezone normalization and conflicting-date
  review. **Repository core delivered;** zoom/range filters, density grouping,
  historical DNS/BGP and snapshot-to-snapshot diff remain open.
- Path finder, neighborhood expansion and graph clustering/community detection.
- Evidence pinning, annotations, attachments and cryptographic evidence hashes.
- Case snapshots and comparison between two investigation dates.
- Saved graph layouts, filters, queries and role-scoped views.
- Entity-resolution suggestions with explainable match signals.
- Case-level watch rules and escalation policies.

### New domain/network intelligence

- RDAP-first registration data with WHOIS fallback and normalized history.
- DNSSEC validation and detailed SPF/DMARC/DKIM/MTA-STS/TLS-RPT/BIMI posture.
- Certificate chain, CT timeline and unexpected issuer/SAN monitoring.
- ASN/BGP prefix ownership, RPKI validity and route-change alerts.
- Passive DNS provider adapters with explicit licensing and retention controls.
- Reverse DNS, nameserver and MX infrastructure relationship graphs.
- Safe HTTP technology/header/favicon fingerprints with provenance.
- Cloud/storage exposure checks limited to non-invasive metadata requests.
- Subdomain takeover indicators with manual-verification workflow.
- Domain lookalike/typosquat campaigns with registration and mail posture.

### Threat-intelligence interoperability

- IOC lists and watchlists with severity, owner, expiry and suppression.
- STIX 2.1 import/export and TAXII client/server integration.
- MISP-compatible event export and sighting ingestion.
- AbuseIPDB/VirusTotal/Shodan result normalization and source attribution.
- Enrichment pipeline for IP/domain/hash/email without silent pivots.
- Rule engine for compound detections across providers and time windows.
- ATT&CK technique mapping only where evidence supports it.
- Feed freshness, license and redistribution metadata.

### Reporting

- Report builder with sections, filters, branding and reusable templates.
- Scheduled encrypted report delivery with recipient confirmation.
- Executive, technical, compliance and incident-response report profiles.
- PDF/HTML/JSON/CSV/STIX bundles with manifest and SHA-256 checksums.
- Redaction presets and audience-specific views.
- Evidence appendix with timestamps, provenance and confidence rationale.
- Share portal with access log, download limits, watermark and revocation.
- Optional client-side encrypted share package for highly sensitive cases.

## Phase 4 — user experience and product depth

- Tokenized design system for spacing/type/color/elevation with dark/high-
  contrast themes and visual-regression snapshots.
- Mobile-first navigation with 44px touch targets, safe-area insets, bottom-sheet
  actions, card alternatives for wide tables and no horizontal page overflow.
- Responsive scan/results/report/share/admin screens at 320/375/768/1024/1440px,
  including long identifiers, empty/error/loading/offline states.
- Guided onboarding and demo workspace with synthetic, non-PII data.
- Unified command palette and complete keyboard navigation.
- WCAG 2.2 AA accessibility pass, screen-reader graph alternatives.
- Romanian/English localization architecture and translated UI/content.
- Responsive investigation table as an alternative to the force graph.
- Saved searches, advanced query language and reusable filter chips.
- Custom dashboards/widgets with shareable read-only views.
- Notification inbox with grouping, acknowledge, snooze and escalation.
- Email/Slack/Discord/Telegram digest schedules and quiet hours.
- PWA install/offline shell; never cache sensitive API responses.
- Optimistic UI with explicit job states and recoverable errors.
- Export progress, cancellation and background completion notification.
- Admin support tools with safe impersonation prohibition and audit context.
- Provider status page and per-plugin incident banners.
- API explorer with scoped temporary tokens and copy-safe examples.
- Versioned API, SDK generation and webhook playground.
- Installable PWA update UX with explicit version/rollback messaging; cache only
  public shell assets and never OSINT/account/API responses.

## Phase 5 — operations, scale and disaster recovery

- OpenTelemetry traces across request, queue, plugin and provider calls.
- Structured security-event stream separated from general application logs.
- SLOs for API availability, scan latency, queue delay and report generation.
- Error-budget alerts and dependency-specific burn-rate dashboards.
- PostgreSQL PITR with encrypted WAL archive and tested point-in-time restore.
- Tiered backup retention (daily/weekly/monthly) plus immutable offsite storage.
- Quarterly disaster-recovery game day with recorded RTO/RPO results.
- PgBouncer, index/query regression tracking and slow-query budgets.
- Read replicas only after authorization-consistent routing is proven.
- Blue/green or canary releases with schema compatibility gates.
- Multi-zone deployment and queue workers only when single-host recovery is solid.
- Capacity model for SSE connections, subprocesses, DB pool and provider quotas.
- Chaos tests for provider timeouts, DNS failures, queue loss and worker death.
- Configuration drift detection for `/etc`, Cloudflare and GitHub Environment.
- Automated certificate, domain, backup, timer and origin-guard expiry checks.

## Phase 6 — privacy, governance and abuse resistance

- Explicit acceptable-use policy and purpose confirmation before sensitive scans.
- Target classes/policies: self, organization-owned, public-interest and blocked.
- Abuse report/takedown workflow with response SLA and preservation policy.
- Consent/legal-basis record for recurring monitoring and notifications.
- Per-data-class retention, legal hold and deletion verification.
- Data-subject access/export/deletion workflow with identity verification.
- Regional storage and subprocess-provider disclosure inventory.
- Provider terms/license register and automatic feature disable on expiry.
- Privacy-preserving analytics with no scan targets or raw findings.
- Admin review queue for high-volume, high-risk or policy-triggered scans.
- Tamper-evident audit export and documented incident-response playbooks.
- Threat model review required for every new plugin/egress destination.

## Suggested delivery waves

| Wave | Duration | Outcome |
|---|---:|---|
| A | 1 week | Close live P0s, verified restore, origin lock, separated identities |
| B | 2–3 weeks | Atomic releases, explicit migrations, security CI and central alerts |
| C | 4–6 weeks | Durable queue/workers, distributed limits, cancellation and plugin health |
| D | 6–10 weeks | Teams/cases/RBAC, evidence provenance, graph/timeline depth |
| E | continuous | New intelligence adapters, UX, compliance and scale based on measured demand |

## Feature admission checklist

Every feature or plugin must answer these before implementation:

1. What data and actor is trusted? What is attacker-controlled?
2. What authorization rule applies to every read and mutation?
3. What is the maximum request, fan-out, output, storage and runtime cost?
4. What external destinations and secrets are required?
5. How are timeout, cancellation, retry and duplicate delivery handled?
6. What PII is stored, encrypted, logged, exported and eventually deleted?
7. How is the feature observed and how does an operator disable it quickly?
8. What tests prove tenant isolation, SSRF resistance and failure behavior?
9. What migration/rollback/backup implications exist?
10. What abuse, legal, provider-terms and user-consent constraints apply?
