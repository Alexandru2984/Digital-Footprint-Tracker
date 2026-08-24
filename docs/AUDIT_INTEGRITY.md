# Signed audit integrity

The normal `audit_logs` table remains readable by administrators and subject to
privacy redaction plus 90-day retention. A second, privacy-minimal ledger commits
to each display row without storing its target, IP address or ciphertext. Every
ledger event is linked to the previous SHA-256 digest and signed with Ed25519.
Low-entropy fields are committed with HMAC-SHA256, so a stolen database cannot
be used to test guessed email addresses, usernames or IP addresses offline.

This detects database-only modification, deletion, insertion and reordering as
long as the active private key remains outside the database. It does not make a
database administrator physically incapable of dropping the entire database;
backups and a remote signed checkpoint are still required for that threat.

## Required production configuration

Generate a key through a protected operator channel, not in shell history or a
ticket:

```text
AUDIT_SIGNING_KEY=<64 lowercase hexadecimal characters from 32 random bytes>
AUDIT_SIGNING_KEY_ID=audit-2026-q3
AUDIT_COMMITMENT_KEY=<another independently generated 64-character hex key>
```

`AUDIT_SIGNING_KEY` is a raw Ed25519 private seed. `AUDIT_COMMITMENT_KEY` is a
stable HMAC secret that must remain unchanged across normal signing-key and
encryption-key rotations. Generate all three secrets independently; reusing any
of them collapses security boundaries. Production startup fails before
migrations or routes when an audit variable is missing, partial or malformed.
Development may omit all three, in which case the legacy display log remains
available but the signed ledger is explicitly disabled.

## Write and verification semantics

- The display row and signed `entry` event commit in one database transaction.
- PostgreSQL serializes all writers through the singleton chain head using
  `FOR UPDATE`; SQLite transactions provide the deterministic test path.
- PostgreSQL and SQLite triggers reject update/delete of ledger events.
- Account erasure appends a signed `redaction` commitment in the same transaction
  as each privacy rewrite.
- Retention appends a signed tombstone before deleting a display row.
- A full verifier checks sequence continuity, every previous hash, every
  signature, the mutable head, legal state transitions and every retained
  display-row commitment. Pre-migration display rows are reported separately as
  `legacyUntrackedLogs` and are not represented as cryptographically protected.
- Display-row commitments use the separate stable HMAC key; neither raw PII nor
  a dictionary-testable plain digest is written to the ledger.
- Verification is bounded at 250,000 ledger/display rows. Crossing the bound
  returns `verification_limit_exceeded` instead of risking unbounded memory.

The service verifies at boot and every five minutes. An administrator with a
recent session can also run an immediate check:

```http
GET /api/admin/audit/integrity
```

The response is intentionally metadata-only: `status`, a bounded failure code,
verified count, legacy count, last sequence, head hash, key ID and timestamp.
Prometheus exposes the last result and alerts on stale/invalid verification or
any rolled-back audit write.

## Rotation

1. Preserve an authenticated backup and a successful integrity response.
2. Generate a new independent seed and unique key ID.
3. Update the signing seed and signing key ID atomically, leave
   `AUDIT_COMMITMENT_KEY` unchanged, then restart through the normal release
   gate. Startup locks the head and appends `audit_signing_key_activated`, signed
   by the new trusted key over the prior immutable tail.
4. Require `status=valid`, the new `activeSigningKeyID`, and an increased
   sequence before accepting the release.
5. Retire the old private seed only after the new checkpoint and off-host backup
   are verified. Historical signatures need only their chained public keys.

Rollback restores the prior application release and both prior signing-key
variables together while retaining the same commitment key. Never change only
the key ID or only the private seed. Commitment-key rotation requires an
explicit whole-ledger recommitment design and is intentionally not automatic.

## Production acceptance

Repository tests are not live evidence. Before deployment acceptance, capture:

- the migration SHA and successful explicit migration unit;
- one valid admin verification response before and after a controlled key
  rotation (without recording private material);
- Prometheus scrape presence plus a delivered test alert;
- a restore-drill verification of the same chain head; and
- a remote/off-host signed checkpoint so whole-database rollback is detectable.
