import Fluent
import Foundation
import SQLKit
import Vapor

enum NotificationRetryPolicy {
    enum Decision: Equatable, Sendable {
        case succeeded
        case skipped
        case retry(at: Date)
        case deadLetter
    }

    static func decision(
        for result: NotificationAttemptResult,
        attemptCount: Int,
        maxAttempts: Int,
        jobID: UUID,
        now: Date
    ) -> Decision {
        switch result.outcome {
        case .succeeded:
            return .succeeded
        case .skipped:
            return .skipped
        case .failed:
            guard result.isRetryable, attemptCount < maxAttempts else {
                return .deadLetter
            }
            return .retry(at: nextAttempt(attemptCount: attemptCount, jobID: jobID, now: now))
        }
    }

    /// Exponential backoff (10 s base, one-hour cap) plus deterministic 0–20%
    /// jitter. Determinism makes incident reconstruction and tests repeatable;
    /// the job UUID still spreads a fleet's retries across the interval.
    static func nextAttempt(attemptCount: Int, jobID: UUID, now: Date) -> Date {
        let exponent = min(max(attemptCount - 1, 0), 12)
        let base = min(3_600.0, 10.0 * pow(2.0, Double(exponent)))
        let digest = sha256Hex("\(jobID.uuidString.lowercased())|\(attemptCount)")
        let prefix = String(digest.prefix(8))
        let bucket = UInt32(prefix, radix: 16) ?? 0
        let jitter = Double(bucket % 2_001) / 10_000.0
        return now.addingTimeInterval(min(3_600.0, base * (1.0 + jitter)))
    }
}

/// Database-backed notification worker. PostgreSQL claims use
/// `FOR UPDATE SKIP LOCKED`, so every web/worker process may run one safely.
/// Leases recover work after crashes; external delivery remains at-least-once
/// because not every provider honours the stable Idempotency-Key header.
actor NotificationDeliveryWorker: LifecycleHandler {
    private var loopTask: Task<Void, Never>?
    private let workerID = UUID().uuidString.lowercased()
    private var nextPurgeAt = Date.distantPast

    nonisolated func didBoot(_ application: Application) throws {
        guard application.notificationDeliveryConfiguration.enabled else {
            application.logger.notice("[NotificationWorker] Disabled by configuration.")
            return
        }
        let app = application
        Task { await self.start(app: app) }
    }

    nonisolated func shutdown(_ application: Application) {
        Task { await self.stop() }
    }

    private func start(app: Application) {
        guard loopTask == nil else { return }
        let pollNanoseconds = UInt64(app.notificationDeliveryConfiguration.pollSeconds) * 1_000_000_000
        loopTask = Task { [weak self] in
            guard let self else { return }
            app.logger.notice("[NotificationWorker] Durable delivery worker started.")
            while !Task.isCancelled {
                await self.tick(app: app)
                try? await Task.sleep(nanoseconds: pollNanoseconds)
            }
        }
    }

    private func stop() {
        loopTask?.cancel()
        loopTask = nil
    }

    private func tick(app: Application) async {
        if Date() >= nextPurgeAt {
            await Self.purgeTerminalEvents(app: app)
            nextPurgeAt = Date().addingTimeInterval(3_600)
        }

        // Bound each tick so a busy queue cannot monopolize one process.
        for _ in 0..<10 {
            do {
                guard try await Self.processNext(
                    app: app,
                    workerID: workerID,
                    now: Date()
                ) != nil else { return }
            } catch {
                app.logger.error("[NotificationWorker] A delivery tick failed safely.")
                return
            }
        }
    }

    @discardableResult
    static func processNext(
        app: Application,
        workerID: String,
        now: Date = Date()
    ) async throws -> UUID? {
        let configuration = app.notificationDeliveryConfiguration
        guard let job = try await claimNext(
            on: app.db,
            workerID: workerID,
            now: now,
            leaseSeconds: configuration.leaseSeconds
        ), let jobID = job.id else { return nil }

        let attemptStartedAt = Date()
        let result: NotificationAttemptResult
        if let channel = job.channel,
           let event = try await NotificationOutboxEvent.find(job.$event.id, on: app.db),
           let user = try await User.find(event.$user.id, on: app.db) {
            do {
                let payload = try event.payload
                result = await NotificationDispatcher.deliver(
                    channel: channel,
                    user: user,
                    title: payload.title,
                    message: payload.message,
                    webhookBody: payload.webhookBody,
                    scanID: event.scanID,
                    deliveryID: jobID,
                    app: app
                )
            } catch let failure as FieldCrypto.DecryptionFailure {
                await SensitiveFieldFailureReporter.report(
                    failure,
                    app: app,
                    context: "notification_outbox"
                )
                result = .failed(.permanent, code: "payload_unreadable")
            } catch {
                result = .failed(.permanent, code: "payload_invalid")
            }
        } else {
            result = .failed(.permanent, code: "invalid_job_reference")
        }

        try await finish(
            jobID: jobID,
            workerID: workerID,
            attemptCount: job.attemptCount,
            maxAttempts: job.maxAttempts,
            result: result,
            now: now.addingTimeInterval(
                max(0, Date().timeIntervalSince(attemptStartedAt))
            ),
            on: app.db
        )
        return jobID
    }

    /// Atomically claims one due row. Expired final-attempt leases are moved to
    /// DLQ first; otherwise a crash after the last provider call would strand a
    /// row in `processing` forever.
    static func claimNext(
        on database: Database,
        workerID: String,
        now: Date,
        leaseSeconds: Int
    ) async throws -> NotificationDeliveryJob? {
        guard let sql = database as? SQLDatabase else { return nil }
        try await expireExhaustedLeases(on: sql, now: now)
        let leaseExpiresAt = now.addingTimeInterval(TimeInterval(leaseSeconds))
        let rows: [any SQLRow]

        if sql.dialect.name.lowercased().contains("postgres") {
            rows = try await sql.raw("""
                WITH candidate AS (
                    SELECT id
                    FROM notification_delivery_jobs
                    WHERE attempt_count < max_attempts
                      AND (
                        (status = \(bind: NotificationDeliveryJobStatus.pending.rawValue)
                         AND next_attempt_at <= \(bind: now))
                        OR
                        (status = \(bind: NotificationDeliveryJobStatus.processing.rawValue)
                         AND lease_expires_at IS NOT NULL
                         AND lease_expires_at <= \(bind: now))
                      )
                    ORDER BY next_attempt_at ASC, created_at ASC, id ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE notification_delivery_jobs AS job
                SET status = \(bind: NotificationDeliveryJobStatus.processing.rawValue),
                    attempt_count = job.attempt_count + 1,
                    lease_owner = \(bind: workerID),
                    lease_expires_at = \(bind: leaseExpiresAt),
                    updated_at = \(bind: now)
                FROM candidate
                WHERE job.id = candidate.id
                RETURNING job.id
                """).all()
        } else {
            // SQLite serializes writers; the single UPDATE with a scalar
            // candidate subquery is therefore sufficient for concurrency tests.
            rows = try await sql.raw("""
                UPDATE notification_delivery_jobs
                SET status = \(bind: NotificationDeliveryJobStatus.processing.rawValue),
                    attempt_count = attempt_count + 1,
                    lease_owner = \(bind: workerID),
                    lease_expires_at = \(bind: leaseExpiresAt),
                    updated_at = \(bind: now)
                WHERE id = (
                    SELECT id
                    FROM notification_delivery_jobs
                    WHERE attempt_count < max_attempts
                      AND (
                        (status = \(bind: NotificationDeliveryJobStatus.pending.rawValue)
                         AND next_attempt_at <= \(bind: now))
                        OR
                        (status = \(bind: NotificationDeliveryJobStatus.processing.rawValue)
                         AND lease_expires_at IS NOT NULL
                         AND lease_expires_at <= \(bind: now))
                      )
                    ORDER BY next_attempt_at ASC, created_at ASC, id ASC
                    LIMIT 1
                )
                RETURNING id
                """).all()
        }

        guard let row = rows.first,
              let id = try? row.decode(column: "id", as: UUID.self) else { return nil }
        return try await NotificationDeliveryJob.find(id, on: database)
    }

    private static func expireExhaustedLeases(on sql: SQLDatabase, now: Date) async throws {
        try await sql.raw("""
            UPDATE notification_delivery_jobs
            SET status = \(bind: NotificationDeliveryJobStatus.deadLetter.rawValue),
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_failure_code = \(bind: "lease_expired_after_final_attempt"),
                completed_at = \(bind: now),
                updated_at = \(bind: now)
            WHERE id IN (
                SELECT id FROM notification_delivery_jobs
                WHERE status = \(bind: NotificationDeliveryJobStatus.processing.rawValue)
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= \(bind: now)
                  AND attempt_count >= max_attempts
                ORDER BY lease_expires_at ASC, id ASC
                LIMIT 100
            )
            """).run()
    }

    static func finish(
        jobID: UUID,
        workerID: String,
        attemptCount: Int,
        maxAttempts: Int,
        result: NotificationAttemptResult,
        now: Date,
        on database: Database
    ) async throws {
        let decision = NotificationRetryPolicy.decision(
            for: result,
            attemptCount: attemptCount,
            maxAttempts: maxAttempts,
            jobID: jobID,
            now: now
        )
        guard let sql = database as? SQLDatabase else { return }
        let failureCode = boundedFailureCode(result.failureCode) ?? "delivery_failed"
        let updatedRows: [any SQLRow]
        let metricStatus: String
        switch decision {
        case .succeeded:
            updatedRows = try await sql.raw("""
                UPDATE notification_delivery_jobs
                SET status = \(bind: NotificationDeliveryJobStatus.succeeded.rawValue),
                    lease_owner = NULL, lease_expires_at = NULL,
                    last_failure_code = NULL, completed_at = \(bind: now), updated_at = \(bind: now)
                WHERE id = \(bind: jobID)
                  AND status = \(bind: NotificationDeliveryJobStatus.processing.rawValue)
                  AND lease_owner = \(bind: workerID)
                RETURNING id
                """).all()
            metricStatus = "succeeded"
        case .skipped:
            updatedRows = try await sql.raw("""
                UPDATE notification_delivery_jobs
                SET status = \(bind: NotificationDeliveryJobStatus.skipped.rawValue),
                    lease_owner = NULL, lease_expires_at = NULL,
                    last_failure_code = NULL, completed_at = \(bind: now), updated_at = \(bind: now)
                WHERE id = \(bind: jobID)
                  AND status = \(bind: NotificationDeliveryJobStatus.processing.rawValue)
                  AND lease_owner = \(bind: workerID)
                RETURNING id
                """).all()
            metricStatus = "skipped"
        case let .retry(nextAttempt):
            updatedRows = try await sql.raw("""
                UPDATE notification_delivery_jobs
                SET status = \(bind: NotificationDeliveryJobStatus.pending.rawValue),
                    next_attempt_at = \(bind: nextAttempt),
                    lease_owner = NULL, lease_expires_at = NULL,
                    last_failure_code = \(bind: failureCode), completed_at = NULL,
                    updated_at = \(bind: now)
                WHERE id = \(bind: jobID)
                  AND status = \(bind: NotificationDeliveryJobStatus.processing.rawValue)
                  AND lease_owner = \(bind: workerID)
                RETURNING id
                """).all()
            metricStatus = "retry_scheduled"
        case .deadLetter:
            updatedRows = try await sql.raw("""
                UPDATE notification_delivery_jobs
                SET status = \(bind: NotificationDeliveryJobStatus.deadLetter.rawValue),
                    lease_owner = NULL, lease_expires_at = NULL,
                    last_failure_code = \(bind: failureCode),
                    completed_at = \(bind: now), updated_at = \(bind: now)
                WHERE id = \(bind: jobID)
                  AND status = \(bind: NotificationDeliveryJobStatus.processing.rawValue)
                  AND lease_owner = \(bind: workerID)
                RETURNING id
                """).all()
            metricStatus = "dead_letter"
        }
        // A stale worker loses this compare-and-set after a peer re-leases the
        // row. It must neither overwrite state nor increment a false metric.
        guard !updatedRows.isEmpty else { return }
        await MetricsRegistry.shared.incNotificationJobTransition(status: metricStatus)
    }

    private static func boundedFailureCode(_ value: String?) -> String? {
        guard let value else { return nil }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789_")
        let normalized = value.lowercased().unicodeScalars.filter(allowed.contains)
        return String(String.UnicodeScalarView(normalized).prefix(64))
    }

    private static func purgeTerminalEvents(app: Application) async {
        guard let sql = app.db as? SQLDatabase else { return }
        let cutoff = Date().addingTimeInterval(
            -Double(app.notificationDeliveryConfiguration.retentionDays) * 86_400
        )
        do {
            try await sql.raw("""
                DELETE FROM notification_outbox_events
                WHERE id IN (
                    SELECT event.id
                    FROM notification_outbox_events AS event
                    WHERE event.created_at < \(bind: cutoff)
                      AND NOT EXISTS (
                        SELECT 1 FROM notification_delivery_jobs AS job
                        WHERE job.event_id = event.id
                          AND job.status IN (
                            \(bind: NotificationDeliveryJobStatus.pending.rawValue),
                            \(bind: NotificationDeliveryJobStatus.processing.rawValue)
                          )
                      )
                    ORDER BY event.created_at ASC
                    LIMIT 100
                )
                """).run()
        } catch {
            app.logger.error("[NotificationWorker] Terminal-event retention sweep failed.")
        }
    }
}

private struct NotificationDeliveryWorkerKey: StorageKey {
    typealias Value = NotificationDeliveryWorker
}

extension Application {
    var notificationDeliveryWorker: NotificationDeliveryWorker {
        if let existing = storage[NotificationDeliveryWorkerKey.self] { return existing }
        let worker = NotificationDeliveryWorker()
        storage[NotificationDeliveryWorkerKey.self] = worker
        return worker
    }
}
