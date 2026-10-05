# Isolated database recovery drill

`scripts/check-backup.sh` proves freshness and authenticated decryptability. It
does **not** prove that PostgreSQL can restore and read the dump. Before any
production rollout, run `scripts/restore-drill.sh` against the newest encrypted
artifact and retain its JSON manifest with the off-host backup copy.

The helper starts the repository-pinned PostgreSQL image with no network, no
host mounts and tmpfs-only database storage. It streams GPG decryption and gzip
decompression directly into `psql`, reads the restored database back through
`pg_dump`, destroys the container, and only then atomically publishes a mode
`0600` success manifest. It refuses symlink/permissive inputs, mutable image
tags and existing manifest paths. It never writes a plaintext dump to disk and
never connects to the host PostgreSQL instance.

## Preconditions

1. A fresh `footprint-*.sql.gz.gpg` passes `scripts/check-backup.sh`.
2. The passphrase is available through a private mode-`0600` file or a systemd
   `LoadCredentialEncrypted=` mount. Never put it in argv, shell history or an
   environment variable.
3. The exact digest already used by `docker-compose.yml` is present locally.
   Derive it rather than copying it — the literal is what went stale:

   ```bash
   docker pull "$(awk '$1 == "image:" && $2 ~ /^postgres:/ { print $2; exit }' docker-compose.yml)"
   ```

   That image must be the PostgreSQL major this host's `pg_dump` writes, or a
   newer one: a dump restores into its own major or newer, never older. The pin
   sat on 16 while the server moved to 18, and every drill failed with
   `unrecognized configuration parameter "transaction_timeout"` until
   2026-10-05. `scripts/tests/restore-drill.test.sh` keeps the drill's pin equal
   to `docker-compose.yml`, and `production-preflight.sh` compares it against
   the `pg_dump` that writes the artifacts.

4. Create a private evidence directory on a filesystem with enough free memory
   for the disposable 2 GiB tmpfs ceiling:

   ```bash
   sudo systemd-tmpfiles --create ops/tmpfiles.d/swift-vapor-backup.conf
   ```

## Run and verify

When using a private passphrase file, run:

```bash
sudo scripts/restore-drill.sh \
  --backup /var/lib/swift-vapor-backup/artifacts/footprint-YYYY-MM-DD_HH-MM-SS.sql.gz.gpg \
  --passphrase-file /run/swift-vapor-backup-passphrase \
  --manifest /var/lib/swift-vapor-recovery/restore-drills/restore-YYYY-MM-DDTHH-MM-SSZ.json
```

For the installed encrypted systemd credential, launch the helper from a
transient unit with the same `LoadCredentialEncrypted=backup-passphrase:...`
property and omit `--passphrase-file`; the helper consumes
`$CREDENTIALS_DIRECTORY/backup-passphrase` automatically.

Treat only exit code `0` plus a newly created manifest as success. Review at
least `backup.sha256`, `duration_seconds`, `public_base_table_count`,
`logical_readback_sha256`, `database_disposed_before_success` and the pinned
image digest. Copy the encrypted artifact and manifest to an owner-approved,
immutable off-host destination, then test retrieval without relying on the VPS.

The manifest contains hashes, counts, times and tool provenance, but no database
rows, credentials or host paths. A failed drill publishes no success manifest;
the original encrypted artifact is always preserved for investigation/retry.


## Restoring from the off-host copy

`swift-vapor-offsite.service` uploads every artifact to the destination named in
`/etc/swift-vapor/offsite.env` after each verified backup, then re-reads the far
side and compares checksums before recording success. It never deletes there, so
the destination holds everything local retention has already rotated away.

There are two destinations, and either is sufficient — the artifacts are
identical. From any machine with rclone and access to one of them:

```bash
# Google Drive
rclone lsl gdrive:Backup_VPS/swift-vapor
rclone copy gdrive:Backup_VPS/swift-vapor/footprint-YYYY-MM-DD_HH-MM-SS.sql.gz.gpg .

# or Cloudflare R2, which needs no OAuth and so survives a retired client id
rclone lsl r2:micutu-vps-backup/swift-vapor
rclone copy r2:micutu-vps-backup/swift-vapor/footprint-YYYY-MM-DD_HH-MM-SS.sql.gz.gpg .

sha256sum footprint-YYYY-MM-DD_HH-MM-SS.sql.gz.gpg
```

Prefer naming the file instead of listing the directory: a listing against
Google Drive through rclone's shared client id has twice returned empty with a
zero exit status under rate limiting, which is misleading rather than wrong.

Then decrypt with the backup passphrase and restore as above. The artifact is
byte-identical to the local one, so `scripts/restore-drill.sh` accepts it
unchanged.

### Measured, 2026-10-05

The drill above was run end to end against the **off-host copy** — the artifact
was fetched from Drive by name, not taken from the local directory:

| step | measured |
|---|---|
| retrieve `footprint-2026-10-05_02-00-15.sql.gz.gpg` (40 562 B) from Drive | 4 s |
| decrypt, restore and logical read-back in a disposable PostgreSQL 18 container | 8 s |
| **total data-path RTO** | **12 s** |
| restored database | 22 public base tables, 9 197 247 B |
| integrity | SHA-256 of the Drive copy equals the on-host artifact |

Manifest: `/var/lib/swift-vapor-recovery/restore-drills/offsite-2026-10-05T07-56-54Z.json`.

**RPO is the backup interval: up to 24 hours.** The timer runs daily at 05:00
local, and the off-host copy follows the verified backup within about 30
seconds, so the off-host copy is never meaningfully older than the local one.

**This 12 s is the data path only.** It does not include provisioning a host,
installing the service, or pointing DNS at it. Full service RTO has not been
measured, and claiming 12 s as recovery time would be dishonest.

### The passphrase is the whole recovery

The encrypted artifacts are worthless without the backup passphrase, and the
copy in `/etc/credstore.encrypted/` **cannot help you off this host**:
`systemd-creds` encrypts it to this machine's `/var/lib/systemd/credential.secret`
and, where present, its TPM. The weekly VPS archive tars `/etc` but not
`/var/lib/systemd`, so it does not carry that key either.

An off-host copy whose passphrase exists only on the host it is meant to outlive
is not a backup. Keep the backup passphrase in a password manager or another
off-host store, and prove it by decrypting one downloaded artifact on a machine
that is not this VPS. Until that is done, the off-host copy protects against
losing the *data* on this host, not against losing the host.
