# Production security revalidation — 2026-08-24

## Executive verdict

**BLOCK production rollout and dark-web enablement.** The public Cloudflare path
is healthy and direct IPv4 origin access is denied, but the service currently
has no backup recovery point, no active monitoring path, no immutable release
provenance and no Unix identity separation. Repository work may continue in
small tested commits; production deployment must wait for the Phase 0 recovery
and identity gates below.

This is a read-only delta review against `SECURITY_AUDIT_2026-08-12.md`. No
production configuration, database row, secret, service or Cloudflare setting
was changed while collecting this evidence.

## Observed production state

| Control | Evidence on 2026-08-24 | Consequence |
|---|---|---|
| Public edge | Cloudflare request returns 200; direct origin IPv4 returns 403 | Existing peer guard is effective for the tested IPv4 path |
| Application | Active on `127.0.0.1:8085`; binary mtime is 2026-08-09 | Loopback binding is good, but running source provenance is unknown |
| Deployment | systemd and nginx still execute/serve `/home/micu/swift+vapor`; `/srv/swift-vapor/current` is absent | Frontend, backend and policy can drift independently |
| Runtime identity | `User=micu`; the prepared `swift-vapor` and `swift-voidaccess` accounts do not exist | App compromise reaches personal/deploy files under the same UID |
| Host authority | `micu` retains `(ALL) NOPASSWD: ALL` | A second boundary failure or stolen unrestricted key has root blast radius |
| Backup | timer disabled; encrypted credential, status marker and backup directory all missing | Current recoverable RPO is undefined; host/DB loss can be permanent |
| Last backup attempt | failed on 2026-08-17 because no passphrase credential was available | Backup failure MTTD was approximately seven days and depended on manual review |
| Schema | last applied migration is `App.CreatePluginCache`; new dark-web migrations are not applied | Current backend/schema cannot safely receive the pending feature rollout |
| Monitoring | Prometheus and Alertmanager are inactive and ports 9090/9093 are closed | Repository alert rules do not produce detection or paging |
| Dark-web worker | service is absent/inactive and no listener exists on 8766 | Correct fail-closed state; keep `DARK_WEB_ENABLED=false` |

The live database currently contains 12 users, 3 scans, 35 result rows, 78
audit rows and 11 session rows. Counts are included only to bound immediate
application impact; no target, identity, result or credential value was read.
The same Unix account and VPS also host unrelated applications, so a host-level
incident has a larger, presently unquantified blast radius.

## Repository remediation follow-up

The earlier cursor-SSE finding is remediated in the repository, not in the
running production release. Result writes now create a per-scan monotonic event
inside the same database transaction, including writes from the prior release
during a zero-downtime migration. Streams use strict `Last-Event-ID` validation,
indexed 100-row replay pages, 15-second heartbeats, terminal-only full-result
risk calculation and duplicate-safe browser rendering. SQLite endpoint tests
and an isolated PostgreSQL 16 run with 20 concurrent writers passed without
missing, duplicate or gapped sequences. This does not change the production
BLOCK verdict or any Phase 0 gate above.

The notification-loss finding is also remediated in the repository only.
Automatic verification email, scan webhook, scheduled-monitor and watched-board
delivery now enters an encrypted PostgreSQL outbox with producer and per-channel
unique keys. PostgreSQL claims use `FOR UPDATE SKIP LOCKED`, leases recover
crashed work, retry is bounded/classified, permanent or exhausted work enters an
admin-visible DLQ, and replay requires recent admin authentication and emits an
audit record. A PostgreSQL 16 migration test plus ten concurrent claimers yielded
five jobs with five distinct owners; an expired lease was then recovered at
attempt two. Provider delivery remains honestly at-least-once, and SMTP bounce
ingestion is not implemented. None of this changes the production BLOCK verdict:
the live schema/release still predates these repository changes.

## CISO forcing review

### 1. STRIDE threat model

Top risks by likelihood times impact:

1. **Elevation of privilege — medium likelihood / critical impact.** An
   application RCE or same-UID file disclosure reaches personal/deployment
   state; broad passwordless sudo makes the eventual host-root path complete.
2. **Information disclosure and availability — medium likelihood / high
   impact.** Database corruption, operator error, disk loss or host compromise
   has no current encrypted recovery point and can expose or permanently erase
   retained OSINT and account data.
3. **Tampering/repudiation — medium likelihood / high impact.** The running
   binary has no embedded/recorded commit identity, nginx serves a mutable
   checkout and audit evidence is co-resident with the application database.

Spoofing remains relevant for sessions, API keys and share capabilities. DoS
remains relevant for fan-out scans, subprocesses, streaming queries and exports,
but it does not outrank the demonstrated recovery and privilege failures.

### 2. Blast radius and planning ALE

Worst application case: all current accounts, sessions, scan targets, findings,
audit history and application/provider credentials are disclosed or destroyed.
Worst host case: every co-resident project readable by `micu` is affected and
root access is obtained.

There is not enough incident history or business-cost data for a defensible FAIR
number. For planning only, assume a small-service loss event costs USD 5,000 to
75,000 and occurs 0.1 to 0.5 times/year; the resulting provisional annualized
loss exposure is **USD 500 to 37,500/year**. This range excludes losses belonging
to other applications on the VPS and must not be represented as an accounting
or insurance estimate.

### 3. Detection

- Target MTTD for backup failure/staleness: 10 minutes after the freshness
  threshold or failed timer event.
- Current demonstrated MTTD: approximately seven days, manual.
- Required signal: systemd unit failure plus
  `swift_vapor_backup_fresh == 0` for 10 minutes.
- Required delivery: Alertmanager route to an acknowledged operator channel;
  repository rule files alone are not detection.
- Additional rules: unexpected service SHA/config hash, direct-origin success,
  authentication anomaly, privilege/config change and encryption failures.

### 4. Response

The dark-web component has a scoped kill switch and incident scenarios in
`DARK_WEB_OPERATIONS.md`. There is no evidenced general incident commander,
contact tree, tested database-loss restore runbook, credential-rotation order or
tabletop result. A backup restore and one compromise tabletop are release gates,
not post-launch cleanup.

### 5. Regulatory window

Account identifiers and investigation data can be personal data. Where GDPR
Article 33 applies, supervisory notification is due without undue delay and,
where feasible, within 72 hours after awareness unless the incident is unlikely
to risk individuals' rights and freedoms. The controller still needs a named
privacy contact, assessment template, evidence-preservation checklist and
pre-written user/regulator communications.

### 6. Vendor and supply chain

Cloudflare, GitHub, SMTP delivery, external OSINT providers, package registries
and any future offsite-backup provider cross trust boundaries. The repository
does not evidence an owner, data classes, region, DPA/SCC status, security review
date, terms/license expiry or kill switch for each provider. VoidAccess remains
disabled and adds no live vendor/data transfer in the observed state.

## Phase 0 acceptance gates

Complete and record these in order:

1. Create a portable recovery secret with an owner-controlled offline copy;
   install only its runtime copy as a systemd credential.
2. Produce a new encrypted dump, verify authenticated decryption, restore it
   into an isolated disposable PostgreSQL instance and record measured RPO/RTO.
3. Copy the encrypted artifact off-host to an owner-approved immutable
   destination; test recovery without relying on this VPS.
4. Create the non-login runtime identity, bootstrap immutable `/srv` releases
   and split runtime secrets away from the personal checkout.
5. Replace broad sudo and unrestricted automation keys only while an independent
   root recovery session remains available.
6. Start Prometheus/Alertmanager with a tested operator notification, backup
   freshness alert and service/config drift alert.
7. Build the accepted commit with Swift 6.2, run the explicit migration unit,
   record manifest/config hashes, canary the normal application and rehearse
   rollback.
8. Only then stage the isolated worker and perform the single authorized
   dark-web canary from `DARK_WEB_OPERATIONS.md`.

## Ordered repository delivery backlog

Each item is a separately tested commit; production evidence is recorded apart
from repository completion.

1. Split constant-cost public liveness from local database readiness and make
   deploy/container gates consume readiness.
2. Add a guarded restore-drill helper and machine-readable recovery manifest;
   never delete the only restorable artifact.
3. Replace fatal field-decryption traps with typed request/job failures,
   quarantine signals and security metrics.
4. Introduce crypto envelope v2 with HKDF-separated keys, table/field/row AAD,
   key IDs and resumable rotation.
5. **Delivered in repository; production pending:** convert result streaming to
   an indexed monotonic cursor with bounded batches and `Last-Event-ID` resume.
6. Make notification outcomes truthful: attempted/succeeded/failed metrics,
   channel policy, retry classes and dead-letter handling.
7. Move exports, reports and correlation to bounded asynchronous jobs with
   completeness manifests, expiry and cancellation.
8. Add CI route-authorization classification, cross-tenant IDOR properties,
   secret/SAST/SBOM gates and signed release provenance.
9. Add Playwright mobile/accessibility/CSP coverage at 320, 375, 768 and 1440
   pixels before expanding the UI.
10. After Phase 0, deliver passkeys/session inventory, cases/workspaces/RBAC,
    timelines, evidence provenance, saved searches, notification inbox, PWA
    shell, bilingual UI and provider-health dashboards in the dependency order
    already defined in `ROADMAP.md`.

## Verdict

**RED — BLOCK.** Continue repository remediation, but do not deploy, migrate or
enable the dark-web worker until backup recovery, identity separation and
monitoring have executable evidence.
