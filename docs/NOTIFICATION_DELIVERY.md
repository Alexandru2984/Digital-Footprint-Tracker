# Durable notification delivery

## Contract

Automatic scan, scheduled-monitor, watched-investigation and verification-email
notifications are written to PostgreSQL before the producer finishes. One
encrypted `notification_outbox_events` row holds the bounded title/message and
optional generic-webhook JSON; one `notification_delivery_jobs` row tracks each
selected channel independently.

The queue provides:

- atomic, idempotent enqueue using a producer key hashed at rest;
- one unique job per `(event_id, channel)`;
- cross-process PostgreSQL claims with `FOR UPDATE SKIP LOCKED`;
- a bounded lease so another process recovers work after a crash;
- transient/permanent failure classification;
- exponential retry from 10 seconds to one hour with deterministic 0–20% jitter;
- a fixed per-job attempt ceiling (five by default) and a dead-letter state;
- encrypted payloads covered by the normal resumable key-rotation command;
- cascade deletion with the user or referenced scan;
- terminal-event retention (30 days by default, 100 events per hourly sweep).

The delivery boundary is deliberately described as **at least once**. The same
job UUID is sent as `Idempotency-Key`, `X-Notification-Delivery-ID`, and (for a
generic webhook) `deliveryID`. A receiver that records that value can make its
side effects exactly once. Discord, Slack, Telegram and SMTP do not all promise
to honour an idempotency key, so a process crash after provider acceptance but
before the database update can produce a duplicate. The application must never
claim an impossible exactly-once guarantee.

`POST /auth/notifications/test` remains synchronous on purpose: it gives the
signed-in user an immediate, per-channel configuration result. It does not
pretend that a successful SMTP hand-off proves final mailbox delivery; provider
bounce/complaint ingestion remains a separate roadmap item.

## State machine

```text
pending ──claim──> processing ──accepted──> succeeded
   ▲                    │
   │                    ├──not configured──> skipped
   │                    ├──permanent/max attempts──> dead_letter
   └────backoff─────────┘

processing --expired lease--> processing under a new worker
dead_letter --audited admin replay--> pending (attempt count reset)
```

HTTP 408, 425, 429 and 5xx responses plus network/SMTP transport failures are
transient. Invalid or private destinations, unreadable encrypted credentials,
malformed payloads, incomplete Telegram credentials and other 4xx responses are
permanent. Failure codes are fixed, credential-free labels; URLs, response bodies
and provider error objects are never stored in the job or logged.

## Configuration

| Variable | Default | Accepted range |
|---|---:|---:|
| `NOTIFICATION_WORKER_ENABLED` | `true` | explicit boolean |
| `NOTIFICATION_MAX_ATTEMPTS` | `5` | 1–10 |
| `NOTIFICATION_POLL_SECONDS` | `2` | 1–60 |
| `NOTIFICATION_LEASE_SECONDS` | `60` | 30–300 |
| `NOTIFICATION_RETENTION_DAYS` | `30` | 1–365 |

Present but invalid values fail application boot. Disabling the worker does not
drop queued work; it is useful for a controlled worker cutover, but queue depth
must be monitored while disabled.

## Operations

Prometheus exposes:

- `swift_vapor_notification_jobs_pending`;
- `swift_vapor_notification_jobs_processing`;
- `swift_vapor_notification_jobs_dead_letter`;
- `swift_vapor_notification_expired_leases`;
- `swift_vapor_notification_oldest_pending_age_seconds`;
- `swift_vapor_notification_deliveries_total{channel,outcome}`;
- `swift_vapor_notification_job_transitions_total{status}`.

An administrator with recent authentication may inspect metadata (never the
payload or credential) with:

```text
GET /api/admin/notification-deliveries?status=dead_letter&limit=50
```

After correcting the destination/provider issue, replay one row with:

```text
POST /api/admin/notification-deliveries/{job-id}/retry
```

Replay is audit-logged. Replaying knowingly re-opens the at-least-once boundary,
so the operator should first check the receiver's stable delivery ID.

Starter alerts cover a non-zero DLQ, unrecovered expired leases and a pending
age above five minutes. Provider acceptance latency and SMTP bounce/complaint
webhooks are not yet measured.

## Deployment and rollback

1. Back up and prove restore before changing production schema.
2. Apply `App.CreateNotificationOutbox` through the dedicated migration unit.
3. Confirm both tables, both queue indexes and the two unique constraints.
4. Deploy readers/producers/workers with the worker initially disabled if a
   canary is required.
5. Enable one worker, observe queue/dead-letter metrics, then roll the web fleet.
6. Send a sink notification and prove the stable delivery ID at the receiver.

The schema is additive. An application rollback should disable the new worker
and retain both tables; the old release ignores them, and a later fixed release
can resume their leases. Do not automatically revert the migration in production:
that would permanently delete queued payloads and delivery evidence.

Repository verification on 2026-08-24 covered SQLite idempotency/cascade/lease
and DLQ tests plus a real PostgreSQL 16 migration. Ten concurrent claimers leased
exactly five jobs to five distinct owners, and a deliberately expired lease was
recovered at attempt two. No production database was used.
