# Production security live delta — 2026-08-24

## Verdict

**RED — BLOCK restart, migration, deployment and dark-web enablement.** The edge
path is healthy, but the live process does not satisfy the repository's recovery,
identity, provenance or monitoring controls. `scripts/production-preflight.sh`
confirmed this mechanically: **6 passed, 27 failed, 0 skipped** in full root
mode. A repository fix is not a deployed control.

This delta supplements `SECURITY_AUDIT_2026-08-24.md`. Evidence collection was
read-only and intentionally omitted secret values, account data, database row
content, public keys and origin addresses. The sole earlier live mitigation in
this work session was the CSP repair: the previous root-owned snippet was backed
up, the exact SPA hashes and per-request nonce were installed through the narrow
helper, `nginx -t` passed, nginx reloaded and a production browser check observed
no CSP execution errors.

## Mechanized live evidence

The acceptance preflight currently passes only these controls:

- the application, nginx, Cloudflare Tunnel and Tor services are active;
- nginx syntax is valid;
- `/api/ready` is hidden at the public/onion proxy boundary.

It fails the remaining 27 checks, grouped below:

- dedicated runtime, deploy and backup identities/groups are not installed;
- the non-secret `/etc/swift-vapor/app.env` and encrypted credential set are not
  provisioned;
- application, migration and backup units do not implement the desired isolated
  contract;
- no current encrypted backup, freshness marker or enabled backup timer exists;
- `/srv/swift-vapor/current` and its verified release manifest do not exist;
- the running executable does not match an accepted immutable release;
- internal database readiness and the served-release frontend hash cannot pass
  the new acceptance contract;
- the forced deploy key, root-owned orchestrator and narrow sudo policy are not
  installed;
- the runtime-to-Docker-socket denial cannot pass in the legacy identity model.

The preflight prints only control labels and aggregate counts. It never reads or
prints environment values or credential contents.

## Prioritized findings

| ID | Severity | Live condition | Prepared repository control | Exit evidence |
|---|---|---|---|---|
| P0-01 | Critical | The effective application UID has Docker-control-group access and the Docker socket is reachable. Application RCE therefore has a direct path to host root and every co-resident container. | Dedicated `swift-vapor`, no privileged supplementary groups, and explicit Docker/containerd/Podman socket hiding on app, migration, backup and worker units. | `id` shows no privileged groups; the full preflight proves the runtime cannot read/write the socket; service sandbox is reviewed after restart. |
| P0-02 | Critical | No current encrypted recovery point, success marker, restore proof or immutable off-host copy exists; the timer is inactive. RPO is undefined. | Dedicated `swift-backup`, two encrypted systemd credentials, AEAD stream verification, private retention, freshness gate and networkless restore drill. | New artifact passes the checker, restores successfully, produces a mode-`0600` manifest, and artifact + manifest are retrieved from an owner-approved off-host destination. |
| P0-03 | Critical | The running executable is a deleted/legacy inode and differs from the current checkout binary. Pending migrations and frontend/backend drift make a blind restart non-deterministic. | Commit-named read-only releases, manifests, explicit migration unit, atomic link switch, CSP transition and process/frontend hash checks. | Candidate is built with the pinned Swift toolchain; migration compatibility is reviewed; post-restart `/proc/<pid>/exe`, release manifest and served frontend hashes agree. |
| P0-04 | High | Application, operator and deployment concerns still share a personal UID and flat secret environment. Privileged account authentication does not meet the new password/TOTP acceptance policy. | Dedicated identities, bounded `_FILE` secret loader, encrypted systemd credentials, one-time admin bootstrap credential and existing 2FA implementation. | No runtime secret assignments in `app.env`; credentials are root-private; production administrators use unique strong passwords and TOTP with recovery evidence. |
| P1-01 | High | The PostgreSQL cluster is shared. The application role is bounded, but default database/schema access remains broader than least privilege. | Application-level authorization and encrypted fields are prepared; database ACL closure remains an operator migration. | Explicit role/DB/schema inventory is retained; unnecessary `PUBLIC CONNECT` and `PUBLIC CREATE` are revoked after dependency review; app migrations and runtime still pass. |
| P1-02 | High | Prometheus/Alertmanager, host audit integrity and file-integrity monitoring are not active. Detection still depends on manual review. | Protected metrics, backup/audit-integrity metrics and alert rules exist in the repository. | A real test alert reaches and is acknowledged by the operator; service/config drift, backup failure and audit-chain failure are monitored. |
| P1-03 | High | A reboot is required for the installed kernel and package maintenance remains pending on a shared host. | Resource ceilings and service sandboxes reduce impact but do not replace patching. | Maintenance window completes reboot and updates; edge/onion, database, containers and full application acceptance are revalidated. |
| P1-04 | High | Dozens of unrelated containers share this VPS, expanding incident blast radius and resource contention. | Per-service limits and socket denial are prepared. | Co-tenancy inventory has owners, resource budgets and recovery dependencies; critical workloads are separated when justified. |

No exact password characteristic, hash, credential, database object content,
origin address or provider token is suitable for version control; sensitive
operator-only evidence must live in the private incident/recovery record.

## Repository-only remediation delivered

These commits are prepared locally and are not proof of live deployment:

| Commit | Control |
|---|---|
| `e96948c` | Hide readiness at proxies, consolidate trusted real-IP handling and deny container control sockets. |
| `81cdf13` | Load scalar secrets from bounded, private, non-symlink files and fail closed on ambiguous sources. |
| `b46785e` | Separate runtime/deploy identities, encrypted core credentials, resource ceilings and root-owned forced deployment tooling. |
| `c46b88d` | Isolate encrypted database backups, private retention/checker boundary, timer and recovery evidence paths. |
| `777fa32` | Enforce a read-only full/deploy acceptance preflight before future automatic deployment. |

The broader repository also contains the delivered crypto envelope/rotation,
durable SSE cursor, encrypted notification outbox, bounded exports, signed audit
integrity, responsive browser quality gate and timeline intelligence described
in `ROADMAP.md`. None should be advertised as live until migrations, release
hashes and browser evidence are accepted.

## Validation evidence

- encrypted-backup contract, backup freshness checker and isolated restore drill:
  passed;
- release/CSP transition, production-boundary and VoidAccess contract tests:
  passed;
- Bash syntax and ShellCheck across operational scripts: passed;
- systemd unit parsing plus sysusers/tmpfiles dry-run: passed; backup service
  offline exposure score: `2.7 OK`;
- pinned Gitleaks full-history and staged-tree scans: no leaks;
- pinned Semgrep custom rules: no findings;
- production CSP browser smoke after the narrow live repair: no CSP events;
- current VPS Swift rebuild: **not available** (`swift` is absent from the
  operator PATH/filesystem search). The accepted candidate must therefore be
  built by the pinned CI/container toolchain, not inferred from stale `.build`
  artifacts.

## Mandatory rollout order

1. The owner stores a portable backup passphrase outside the VPS and confirms
   independent root-console recovery.
2. Provision only the backup/database credentials, install the backup identity
   and unit, create a fresh encrypted dump, run the isolated restore drill and
   retrieve an immutable off-host copy.
3. Select replacement administrator credentials through a private handoff,
   enable TOTP and retain recovery codes outside the host.
4. Install the dedicated runtime/deploy identities, root-owned forced command,
   narrow sudoers file, non-secret environment and encrypted application keys.
5. Build the intended commit in the pinned Swift 6.2 environment, verify the
   release manifest and review every pending migration for expand/contract and
   rollback implications.
6. During an announced maintenance window, keep an independent root session
   open, run the explicit migration unit, select the immutable release and
   restart only the application service.
7. Require zero failures from the full production preflight, then run the real
   browser login/2FA/scan/SSE/export/share/revocation/CSP smoke suite.
8. Remove broader personal-account passwordless sudo, enable acknowledged
   monitoring, observe one normal traffic cycle, and only then enable CI deploy.
9. Schedule the kernel reboot as a separate rollback-aware host maintenance
   window; revalidate every co-resident workload afterward.

Migrations are never auto-reverted. Application rollback selects the previous
verified release, restarts the service, restores the prior CSP generation and
repeats readiness/frontend checks. Database restore or migration-specific
compensation requires an explicit operator decision and the tested recovery
artifact.

## Actions intentionally requiring the owner

Automation must stop before creating or choosing the portable backup secret,
off-host immutable destination, replacement administrator password/TOTP recovery
kit, independent console session, paging destination or maintenance window.
Those are security ownership and external-state decisions, not safe defaults.
Until they are provided and evidenced, the correct production action is no
restart, no migration and no deployment.
