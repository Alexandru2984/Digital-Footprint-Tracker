# Durable SSE result streaming

## Contract

`GET /api/stream/:scanID` emits named Server-Sent Events:

- `result` has a positive, monotonically increasing `id` scoped to the scan;
- `progress` is best-effort live state and is intentionally not cursor-bearing;
- `done` is emitted only for the persisted `completed` or `failed` scan state;
- `stream-error` contains a stable code and never includes stored field values.

Clients resume with `Last-Event-ID`. Cursor `0` starts from the beginning. A
malformed cursor or a position outside retained history returns `400`. Replay
is ordered and fetched in pages of at most 100 rows. Each HTTP response ends
before the proxy timeout; native `EventSource` reconnects from its last result
ID. Heartbeat comments are sent every 15 seconds while caught up.

## Persistence and rollout safety

`scan_result_events` stores an internal database identity plus a unique
`(scan_id, stream_sequence)` and one unique row per result. The internal identity
is never exposed, so a client cannot infer application-wide result volume.

The PostgreSQL migration is one transaction:

1. create the additive event table;
2. acquire a five-second-bounded write lock on `results`;
3. install a `BEFORE INSERT` trigger that serializes writers on the parent scan;
4. install an `AFTER INSERT` trigger that assigns the next sequence;
5. backfill historical results with `ROW_NUMBER()`; and
6. commit the table, triggers and backfill atomically.

The split triggers avoid PostgreSQL foreign-key lock-upgrade deadlocks. They
also cover inserts made by the previous application release between migration
and cutover. New code verifies that a cursor was created before committing a
result. Deleting a scan cascades to both results and stream events.

The migration fails safely after a 5-second lock wait or 60-second statement
budget. Investigate long transactions and retry the deployment gate; do not
raise these limits blindly on a busy production database.

## Rollback

Application rollback is additive: switch back to the previous binary but keep
`scan_result_events` and both triggers. The previous binary ignores the table,
while its result inserts remain compatible with a later forward deployment.
Do not run the Fluent migration revert automatically. Reverting intentionally
drops the triggers and table and is only appropriate after confirming that no
deployed binary consumes durable cursors.

## Non-sensitive verification

After migration, verify that both trigger names exist on `results`, then compare
counts without selecting finding content:

```sql
SELECT COUNT(*) FROM results;
SELECT COUNT(*) FROM scan_result_events;
SELECT scan_id, MIN(stream_sequence), MAX(stream_sequence),
       COUNT(*) = COUNT(DISTINCT stream_sequence) AS unique_sequences
FROM scan_result_events
GROUP BY scan_id;
```

For every retained scan, result and event counts must match and sequences must
be unique. Repository tests additionally cover historical backfill, direct
old-writer inserts, rollback on missing parents, cursor rejection and endpoint
replay after `Last-Event-ID`.
