# Dark-web worker operations

The dark-web integration is an opt-in defensive investigation feature. Keep
`DARK_WEB_ENABLED=false` until the isolated worker, backup gate, monitoring and
one controlled canary have all passed. Only investigate targets for which the
operator and requesting user have explicit authorization.

## Trust boundary

- Vapor stores the target and normalized result encrypted in PostgreSQL.
- The web process sends one bounded target to a loopback-only adapter using an
  HMAC-authenticated request with a short replay window.
- The adapter runs VoidAccess through Tor as the dedicated, non-login
  `swift-voidaccess` identity. It has no database, application encryption, SMTP
  or provider credentials.
- Raw pages, scraped URLs, snippets, command output and filesystem paths never
  cross the adapter contract. Jobs expire after at most seven days.

## Prerequisites and fail-closed preflight

1. A recent encrypted database backup passes `scripts/check-backup.sh`, and a
   separate isolated restore drill has succeeded.
2. Tor is active and listens only on the expected local SOCKS port.
3. A trusted, root-owned Python 3.13 runtime is available. The installer rejects
   every other Python minor version. If it is not at `/usr/bin/python3.13`, pass
   its absolute path as `VOIDACCESS_PYTHON_BIN`; do not point root at a runtime
   writable by an unprivileged account.
4. The application already runs as `swift-vapor` from the immutable
   `/srv/swift-vapor/current` layout. Do not install the worker into the legacy
   personal-user deployment.
5. The source archive, spaCy model and Python dependency set remain pinned by
   commit/version and SHA-256 or package hashes in the installer and lockfile.

Run the repository tests before staging:

```bash
shellcheck scripts/install-voidaccess.sh worker/voidaccess-entrypoint.sh
python3 -m py_compile worker/voidaccess_worker.py scripts/tests/voidaccess-worker.test.py
python3 scripts/tests/voidaccess-worker.test.py
```

## Stage without enabling

Create one encrypted credential shared only by the two system services. The
plaintext is piped directly into `systemd-creds` and must not be placed in
`.env`, a command argument, a log or shell history:

```bash
sudo install -d -m 0700 -o root -g root /etc/credstore.encrypted
openssl rand -base64 48 | sudo systemd-creds encrypt \
  --name=dark-web-shared-secret - \
  /etc/credstore.encrypted/swift-vapor-dark-web-shared-secret
sudo chmod 0600 /etc/credstore.encrypted/swift-vapor-dark-web-shared-secret
```

Stage the reviewed runtime. This downloads only pinned artifacts, verifies them,
installs the adapter and unit, and deliberately starts nothing:

```bash
sudo env VOIDACCESS_PYTHON_BIN=/usr/bin/python3.13 scripts/install-voidaccess.sh
sudo systemd-analyze verify \
  /etc/systemd/system/swift-vapor-voidaccess.service \
  ops/systemd/swift-vapor.service
sudo systemd-analyze security swift-vapor-voidaccess.service
```

Confirm `/etc/swift-voidaccess/worker.env` contains only non-secret settings and
is mode `0640`. Install the matching application unit only through the normal
atomic deployment bootstrap; both services must load the same encrypted
credential. Keep these application settings disabled for the first worker boot:

```dotenv
DARK_WEB_ENABLED=false
DARK_WEB_WORKER_URL=http://127.0.0.1:8766
DARK_WEB_RETENTION_HOURS=72
DARK_WEB_MAX_OUTSTANDING=5
DARK_WEB_MAX_JOBS_PER_USER_DAY=3
DARK_WEB_JOB_TIMEOUT_SECONDS=600
```

Then start the worker and inspect only bounded service diagnostics:

```bash
sudo systemctl enable --now swift-vapor-voidaccess.service
sudo systemctl is-active swift-vapor-voidaccess.service tor.service
sudo ss -ltnp | grep ':8766 '
sudo journalctl -u swift-vapor-voidaccess.service -n 50 --no-pager
```

The listener must be `127.0.0.1:8766`, the preflight must report no missing
runtime/model/Tor dependency, and logs must contain no target or scraped data.

## Canary and release gate

1. Enable `DARK_WEB_ENABLED=true` only after the worker is healthy, then restart
   the web service through the normal deployment workflow.
2. Sign in with a verified test account and confirm `/api/dark-web/status`
   reports both `enabled` and `workerHealthy` as true.
3. Submit one harmless target controlled by the operator. Confirm one job at a
   time, bounded completion, normalized results only, cancellation, deletion and
   automatic expiry.
4. Confirm queue/failure metrics, worker restart behavior, CPU/memory/task
   ceilings and operator alert delivery. Do not expand depth, enable an LLM or
   add browser/export plugins during this canary.
5. Record the release commit, migration result, start/end time and operator. Do
   not record the target or result in the deployment log.

## Kill switch and rollback

If health, resource ceilings, output validation or authorization behavior is
wrong, set `DARK_WEB_ENABLED=false` and restart the web service, then stop the
worker:

```bash
sudo systemctl stop swift-vapor-voidaccess.service
```

Disabling the feature cancels pending/running jobs during application recovery;
completed data remains encrypted until normal retention cleanup. Do not drop the
table, delete releases or rotate the encryption key during rollback. Preserve
service/audit logs and the affected release for incident analysis.

If the HMAC credential may be exposed, keep both services stopped, replace the
encrypted credential through a root-only temporary path, restart the worker and
web service together, and repeat the authenticated health canary. An application
or worker compromise also requires rotation of every credential reachable by
that specific service and review of audit integrity.

## Incident response exercise

Tabletop these cases before production enablement:

- the worker emits data outside the normalized schema;
- a job exceeds its deadline or leaves a descendant process alive;
- Tor becomes unavailable while jobs are queued;
- the HMAC credential is disclosed or replay attempts spike;
- a user submits a target without valid authorization;
- PostgreSQL or the host is lost while retained findings exist.

For personal-data incidents, start the breach clock when the controller becomes
aware, preserve evidence, identify affected users/data and involve the privacy
owner immediately. Where GDPR Article 33 applies, supervisory notification is
due without undue delay and, where feasible, within 72 hours unless the breach
is unlikely to risk individuals' rights and freedoms.
