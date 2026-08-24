# Sensitive-field encryption rotation

This runbook covers format migration, root-key rotation, verification, resume,
and rollback for the application's v1/v2 AES-256-GCM envelopes. V2 derives
separate encryption and blind-index keys with HKDF-SHA256 and authenticates the
key ID, storage field, and row UUID.

The repository implementation is designed to fail closed. It never prints a
key, plaintext, or ciphertext. A PostgreSQL advisory lock prevents two rewrap
jobs from running together, each bounded data batch is row-locked, and the data
changes plus cursor are committed in one transaction.

## Non-negotiable preconditions

Do not start a rotation until all of these are true:

1. A fresh encrypted backup has passed authentication/decompression checks and
   an isolated restore has been demonstrated. Preserve the old root separately.
2. Every web and worker process runs the dual v1/v2 reader. No old binary may
   remain in the fleet.
3. Every process has the same explicit `ENCRYPTION_WRITE_VERSION`, active
   `ENCRYPTION_KEY_ID`, active `ENCRYPTION_KEY`, and bounded previous keyring.
4. The `encryption_metadata` migration exists and normal readiness is healthy.
5. The operator has a rollback window, database monitoring, and enough time to
   finish the independent verification pass before removing any old root.

`ENCRYPTION_PREVIOUS_KEYS` contains root keys. Deliver it through the same
secret channel as `ENCRYPTION_KEY`; never paste it into shell history, tickets,
logs, or version control. At most four comma-separated `id=64hex` entries are
accepted. Key IDs are non-secret, unique, and at most 32 safe characters.

## Reader-first v1 to v2 format migration

This changes the envelope format without changing the root:

1. Deploy the dual-reader release everywhere with
   `ENCRYPTION_WRITE_VERSION=1` and a stable `ENCRYPTION_KEY_ID`.
2. Prove the old fleet is fully drained. Set `ENCRYPTION_WRITE_VERSION=2` and
   restart every web/worker process with the same root and ID.
3. Run the rewrap from the accepted immutable release:

   ```bash
   /srv/swift-vapor/current/Run crypto-rewrap --env production \
     --confirm-key-id primary --batch-size 100
   /srv/swift-vapor/current/Run crypto-rewrap --env production \
     --confirm-key-id primary --batch-size 100 --verify-only
   ```

The first command automatically performs a second, active-key-only verification
stage. The separate `--verify-only` run is intentional operational evidence,
not redundant ceremony.

## Root-key rotation

Assume the old ID is `epoch-a` and the new ID is `epoch-b`:

1. Generate and escrow a new independent 32-byte root through the approved
   secret-management path. Keep the verified pre-rotation backup and old root.
2. Configure the whole dual-reader fleet with the new root as
   `ENCRYPTION_KEY`, `ENCRYPTION_KEY_ID=epoch-b`,
   `ENCRYPTION_WRITE_VERSION=2`, and the old root as the secret value
   `ENCRYPTION_PREVIOUS_KEYS=epoch-a=<old-root>`.
3. Restart/drain every web and worker process. Confirm application readiness and
   representative reads/writes before starting bulk rewrap.
4. Run and independently verify:

   ```bash
   /srv/swift-vapor/current/Run crypto-rewrap --env production \
     --confirm-key-id epoch-b --batch-size 100
   /srv/swift-vapor/current/Run crypto-rewrap --env production \
     --confirm-key-id epoch-b --batch-size 100 --verify-only
   ```

5. Take a new encrypted backup and exercise restore/read checks with the new
   root. Archive the completion output and checkpoint evidence.
6. Only now remove `epoch-a` from `ENCRYPTION_PREVIOUS_KEYS`, restart every
   process, and run `--verify-only` once more. Retire the old root according to
   the escrow/retention policy; do not destroy the only key for retained old
   backups.

The command rewrites scan and dark-web blind indexes. Plugin-cache target hashes
cannot be reconstructed without their original input, so the disposable cache
is purged in bounded batches and repopulates under the active index key.

## Resume, time slicing, and failures

Progress is stored as non-secret JSON in `encryption_metadata` under
`sensitive-field-rewrap-v1`. The checkpoint records stage, table phase, UUID
cursor, counts, target format/key ID, and timestamps—never field content.

- An interrupted command resumes when invoked again with the same write version
  and confirmed key ID.
- `--max-batches N` stops cleanly after N checkpointed transactions. Run the
  identical command again to continue.
- `--restart` discards only the saved cursor and idempotently processes all rows
  again. Use it after understanding a corrupt checkpoint or changing the
  maintenance plan; it does not bypass decryption/authentication failures.
- A damaged or unavailable ciphertext stops on its table phase and record UUID.
  The failed transaction does not advance the cursor. Keep every previous key,
  investigate the record, recover it from trusted backup if appropriate, and
  rerun the same command.
- A second concurrent rewrap is rejected by the PostgreSQL session advisory
  lock. Do not bypass that lock or edit checkpoint JSON by hand.

The automatic verification authenticates every non-null sensitive field using
only the active root and required target format, and recomputes persistent scan
and dark-web blind indexes from the authenticated plaintext. Merely being
decryptable—or searchable only—through a previous key does not pass.

## Rollback to a v1-only binary

Never deploy a v1-only binary while any v2 envelope remains.

1. Keep the current dual-reader binary deployed. Select the root the old binary
   will receive as active, retain every other required root in the previous
   keyring, and explicitly set `ENCRYPTION_WRITE_VERSION=1` on all current
   processes.
2. Restart/drain the fleet so every new write is v1.
3. Run `crypto-rewrap` with the active key ID, then a separate `--verify-only`.
   V1 verification performs AES-GCM authentication with only the active root;
   it does not rely on a key ID that v1 lacks.
4. Remove previous keys only after verification and a restored backup test.
5. Deploy the v1-only binary with that exact active root and run its smoke suite.

If rewrap cannot be completed safely, stop the rollout and restore the verified
pre-change database plus its matching release and keys. A database rollback
without matching encryption material is not a rollback.
