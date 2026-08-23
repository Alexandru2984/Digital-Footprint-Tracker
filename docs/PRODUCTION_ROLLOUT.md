# Controlled production rollout

This is the one-time bridge from the legacy checkout-served deployment to
immutable releases. It changes live availability and therefore requires an
announced maintenance window, console access and a second operator/session able
to recover nginx/systemd. Do not paste the sequence blindly: compare every
version-controlled file with its installed counterpart first.

## Mandatory go/no-go gates

Proceed only when all are true:

1. `scripts/check-backup.sh --status-file /var/lib/swift-vapor-backup/last-success`
   passes after a new encrypted backup.
2. That backup has been restored into an isolated PostgreSQL instance and the
   application-level spot checks are recorded. Freshness/integrity is not proof
   of restorability.
3. VPS console access works independently of Cloudflare, nginx and the deploy
   SSH key.
4. `git status --short` is empty and the intended commit is recorded.
5. Every migration in the candidate is expand/contract compatible with the
   previous application release. Otherwise stop and use a bespoke migration
   window.

## Prepare without changing traffic

Create the non-login runtime identity and deploy-owned release directories,
then build and verify the commit-named release as the unprivileged deploy user:

```bash
sudo systemd-sysusers "$PWD/ops/sysusers.d/swift-vapor.conf"
sudo systemd-tmpfiles --create "$PWD/ops/tmpfiles.d/swift-vapor.conf"
commit="$(git rev-parse HEAD)"
scripts/build-release.sh "$commit"
source scripts/release-lib.sh
verify_release "/srv/swift-vapor/releases/$commit" /srv/swift-vapor/releases
```

Install the narrow root helper and validate the sudoers policy before replacing
the existing broad grant. Keep a root console open while changing sudo:

```bash
sudo install -o root -g root -m 0755 ops/libexec/update-swift-csp /usr/local/sbin/update-swift-csp
sudo visudo -cf ops/sudoers/swift-vapor-deploy
sudo install -o root -g root -m 0440 ops/sudoers/swift-vapor-deploy /etc/sudoers.d/swift-vapor-deploy
sudo visudo -c
```

Create both links using the validated helper, then install the migration unit,
application unit/drop-ins and nginx files. Preserve local TLS/onion details when
diffing rather than overwriting unrelated configuration.

```bash
source scripts/release-lib.sh
switch_release_link "/srv/swift-vapor/releases/$commit" /srv/swift-vapor/current /srv/swift-vapor/releases
switch_release_link "/srv/swift-vapor/releases/$commit" /srv/swift-vapor/next /srv/swift-vapor/releases
sudo install -o root -g root -m 0644 ops/systemd/swift-vapor.service /etc/systemd/system/swift-vapor.service
sudo install -o root -g root -m 0644 ops/systemd/swift-vapor-migrate.service /etc/systemd/system/swift-vapor-migrate.service
sudo install -d -o root -g root -m 0755 /etc/systemd/system/swift-vapor.service.d
sudo install -o root -g root -m 0644 ops/systemd/swift-vapor.service.d/*.conf /etc/systemd/system/swift-vapor.service.d/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/swift-vapor.service /etc/systemd/system/swift-vapor-migrate.service
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
