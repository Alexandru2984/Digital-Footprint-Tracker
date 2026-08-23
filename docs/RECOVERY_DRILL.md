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
3. The exact digest already used by `docker-compose.yml` is present locally:

   ```bash
   docker pull 'postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'
   ```

4. Create a private evidence directory on a filesystem with enough free memory
   for the disposable 2 GiB tmpfs ceiling:

   ```bash
   sudo install -d -o root -g root -m 0700 /var/lib/swift-vapor-backup/restore-drills
   ```

## Run and verify

When using a private passphrase file, run:

```bash
sudo scripts/restore-drill.sh \
  --backup /home/micu/swift-vapor-backups/footprint-YYYY-MM-DD_HH-MM-SS.sql.gz.gpg \
  --passphrase-file /run/swift-vapor-backup-passphrase \
  --manifest /var/lib/swift-vapor-backup/restore-drills/restore-YYYY-MM-DDTHH-MM-SSZ.json
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
