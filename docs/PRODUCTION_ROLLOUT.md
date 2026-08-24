# Controlled production rollout

This is the one-time bridge from the legacy checkout-served deployment to
immutable releases. It changes live availability and therefore requires an
announced maintenance window, console access and a second operator/session able
to recover nginx/systemd. Do not paste the sequence blindly: compare every
version-controlled file with its installed counterpart first.

## Mandatory go/no-go gates

Proceed only when all are true:

1. `scripts/check-backup.sh --directory /var/lib/swift-vapor-backup/artifacts --status-file /var/lib/swift-vapor-backup/status/last-success`
   passes after a new encrypted backup. Install the recovery foundation from
   README first; this gate cannot be waived for initial rollout.
2. `scripts/restore-drill.sh` has restored that exact artifact into its
   networkless disposable PostgreSQL instance, and the new mode-`0600` JSON
   manifest from `docs/RECOVERY_DRILL.md` is retained off-host with the backup.
   Freshness/integrity alone is not proof of restorability.
3. VPS console access works independently of Cloudflare, nginx and the deploy
   SSH key.
4. `git status --short` is empty and the intended commit is recorded.
5. Every migration in the candidate is expand/contract compatible with the
   previous application release. Otherwise stop and use a bespoke migration
   window.

## Prepare without changing traffic

Create distinct runtime and deploy identities. The deploy account has a locked
password and a shell only because `sshd` needs one to execute its forced command;
it must never receive an unrestricted key or interactive sudo:

```bash
sudo systemd-sysusers "$PWD/ops/sysusers.d/swift-vapor.conf" \
  "$PWD/ops/sysusers.d/swift-vapor-backup.conf"
sudo systemd-tmpfiles --create "$PWD/ops/tmpfiles.d/swift-vapor.conf" \
  "$PWD/ops/tmpfiles.d/swift-vapor-backup.conf"
getent passwd swift-vapor swift-deploy swift-backup
```

Clone a clean deployment checkout owned only by `swift-deploy`. Do not reuse the
personal working tree and do not copy its `.env`:

```bash
deploy_repo=/var/lib/swift-deploy/repository
sudo -u swift-deploy -H git clone --branch main --single-branch \
  https://github.com/Alexandru2984/Digital-Footprint-Tracker "$deploy_repo"
commit="$(sudo -u swift-deploy -H git -C "$deploy_repo" rev-parse HEAD)"
sudo -u swift-deploy -H "$deploy_repo/scripts/build-release.sh" "$commit"
sudo -u swift-deploy -H bash -c \
  'source "$1/scripts/release-lib.sh"; verify_release "$2" /srv/swift-vapor/releases' \
  _ "$deploy_repo" "/srv/swift-vapor/releases/$commit"
```

Install the non-secret environment template and edit only host-specific routing,
usernames and feature bounds. The negative grep must print nothing:

```bash
sudo install -d -o root -g root -m 0755 /etc/swift-vapor
sudo install -o root -g root -m 0644 \
  "$deploy_repo/ops/environment/swift-vapor.env.example" /etc/swift-vapor/app.env
sudoedit /etc/swift-vapor/app.env
sudo grep -E '^(DATABASE_PASSWORD|ENCRYPTION_KEY|ENCRYPTION_PREVIOUS_KEYS|AUDIT_SIGNING_KEY|AUDIT_COMMITMENT_KEY|ADMIN_PASSWORD|SMTP_PASS|METRICS_TOKEN|DARK_WEB_SHARED_SECRET|[A-Z0-9_]*API_KEY)=' \
  /etc/swift-vapor/app.env
```

Provision the four mandatory values as encrypted, host-bound systemd
credentials. Populate the named plaintext staging files through a trusted
password manager or `sudoedit`; never place values in a command argument,
shell variable, Git file or terminal transcript. `/run` is tmpfs, but remove
the staging files immediately after encryption:

```bash
sudo install -d -o root -g root -m 0700 /run/swift-vapor-credential-staging
sudo install -d -o root -g root -m 0700 /etc/credstore.encrypted
sudoedit /run/swift-vapor-credential-staging/database-password
sudoedit /run/swift-vapor-credential-staging/encryption-key
sudoedit /run/swift-vapor-credential-staging/audit-signing-key
sudoedit /run/swift-vapor-credential-staging/audit-commitment-key
sudo chmod 0600 /run/swift-vapor-credential-staging/*
sudo systemd-creds encrypt --name=database-password \
  /run/swift-vapor-credential-staging/database-password \
  /etc/credstore.encrypted/swift-vapor-database-password
sudo systemd-creds encrypt --name=encryption-key \
  /run/swift-vapor-credential-staging/encryption-key \
  /etc/credstore.encrypted/swift-vapor-encryption-key
sudo systemd-creds encrypt --name=audit-signing-key \
  /run/swift-vapor-credential-staging/audit-signing-key \
  /etc/credstore.encrypted/swift-vapor-audit-signing-key
sudo systemd-creds encrypt --name=audit-commitment-key \
  /run/swift-vapor-credential-staging/audit-commitment-key \
  /etc/credstore.encrypted/swift-vapor-audit-commitment-key
sudo chmod 0600 /etc/credstore.encrypted/swift-vapor-*
sudo rm -f /run/swift-vapor-credential-staging/database-password \
  /run/swift-vapor-credential-staging/encryption-key \
  /run/swift-vapor-credential-staging/audit-signing-key \
  /run/swift-vapor-credential-staging/audit-commitment-key
sudo rmdir /run/swift-vapor-credential-staging
```

An existing database must not carry `ADMIN_PASSWORD` at runtime. For a genuinely
empty database only, encrypt a one-time admin credential and install
`30-admin-bootstrap-credential.conf.example` without the `.example` suffix on
the migration unit. Remove both installed drop-in and encrypted source
immediately after the first successful migration.

Install the deployment orchestrator and its sourced helpers as root-owned files;
the forced command must never resolve through the deploy-writable checkout.
Put exactly one deployment public key in the root-owned
`/var/lib/swift-deploy/.ssh/authorized_keys`, prefixed with
`restrict,command="/usr/local/libexec/swift-vapor/deploy.sh"`. Set the GitHub
production environment's `DEPLOY_USER` to `swift-deploy`. Install the narrow
root helper and sudo policy while an independently authenticated root console
remains open:

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec/swift-vapor
sudo install -o root -g root -m 0755 \
  "$deploy_repo/scripts/deploy.sh" \
  "$deploy_repo/scripts/build-release.sh" \
  "$deploy_repo/scripts/production-preflight.sh" \
  "$deploy_repo/scripts/release-lib.sh" \
  /usr/local/libexec/swift-vapor/
sudoedit /var/lib/swift-deploy/.ssh/authorized_keys
sudo chown root:root /var/lib/swift-deploy/.ssh/authorized_keys
sudo chmod 0644 /var/lib/swift-deploy/.ssh/authorized_keys
sudo install -o root -g root -m 0755 "$deploy_repo/ops/libexec/update-swift-csp" \
  /usr/local/sbin/update-swift-csp
sudo visudo -cf "$deploy_repo/ops/sudoers/swift-vapor-deploy"
sudo install -o root -g root -m 0440 "$deploy_repo/ops/sudoers/swift-vapor-deploy" \
  /etc/sudoers.d/swift-vapor-deploy
sudo visudo -c
```

Only after a second root session proves recovery, remove every broader
`NOPASSWD: ALL` rule from the personal account. Confirm `swift-deploy` can run
only the three commands in the committed alias and cannot obtain a shell as
root.

Create both release links, then install the application and migration units.
Install only real `*.conf` drop-ins; files ending in `.conf.example` are inert
templates and must not be copied. Preserve local TLS/onion details when diffing
nginx rather than overwriting unrelated configuration:

```bash
sudo -u swift-deploy -H bash -c 'source "$1/scripts/release-lib.sh"; \
  switch_release_link "$2" /srv/swift-vapor/current /srv/swift-vapor/releases; \
  switch_release_link "$2" /srv/swift-vapor/next /srv/swift-vapor/releases' \
  _ "$deploy_repo" "/srv/swift-vapor/releases/$commit"
sudo install -o root -g root -m 0644 "$deploy_repo/ops/systemd/swift-vapor.service" \
  /etc/systemd/system/swift-vapor.service
sudo install -o root -g root -m 0644 "$deploy_repo/ops/systemd/swift-vapor-migrate.service" \
  /etc/systemd/system/swift-vapor-migrate.service
sudo install -d -o root -g root -m 0755 /etc/systemd/system/swift-vapor.service.d
sudo install -o root -g root -m 0644 \
  "$deploy_repo/ops/systemd/swift-vapor.service.d/10-hardening.conf" \
  "$deploy_repo/ops/systemd/swift-vapor.service.d/20-bind-loopback.conf" \
  /etc/systemd/system/swift-vapor.service.d/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/swift-vapor.service \
  /etc/systemd/system/swift-vapor-migrate.service
sudo nginx -t
```

## Cut over and verify

Run the explicit migration unit first. Then restart the app, reload nginx and
verify the loopback backend plus the onion listener (which proves nginx is
reading the selected frontend rather than the checkout):

```bash
sudo systemctl start swift-vapor-migrate.service
sudo systemctl restart swift-vapor.service
sudo systemctl reload nginx
curl --fail --silent --show-error http://127.0.0.1:8085/ready
curl --fail --silent --show-error -H 'Host: 5jyd4lflkewyc3gm42uxvi2aryh5g2l4ib2pm5uewpff3ld7yfii5iid.onion' \
  http://127.0.0.1:8110/index.html | sha256sum
sha256sum "/srv/swift-vapor/releases/$commit/frontend/index.html"
```

Compare the two frontend hashes, test login/scan/report/share revocation from a
real browser, verify Prometheus scraping and watch logs/error rates for at least
one normal traffic cycle. Only then enable the CI deploy path.

Run the full root acceptance gate after cutover. It must report zero failures;
unlike `--deployment-gate`, full mode also proves credential/source modes,
root-owned SSH/orchestrator files, sudoers syntax, nginx syntax and Docker-socket
inaccessibility. It prints labels only, never secret or environment values:

```bash
sudo /usr/local/libexec/swift-vapor/production-preflight.sh \
  --repository /var/lib/swift-deploy/repository
```

For the clearnet response, fetch two uncached HTML responses and confirm that
the CSP `nonce-...` values differ. Cloudflare JavaScript Detections must remain
present under `/cdn-cgi/challenge-platform/`, and every Cloudflare-injected
inline `<script>` must carry the nonce from the same response header. Treat a
CSP console error or a missing/mismatched nonce as a failed rollout. Never work
around this with `script-src 'unsafe-inline'` or by pinning the transient
Cloudflare bootstrap hash.

## Rollback

Keep the previous release path recorded before cutover. For an application or
frontend regression, atomically switch `current` back, restart, restore the old
CSP hashes with `scripts/update-csp-hashes.sh OLD_RELEASE/frontend`, and repeat
the health/static checks. Do not run Fluent migration reverts automatically:
database rollback requires a migration-specific decision or the tested database
restore procedure.
