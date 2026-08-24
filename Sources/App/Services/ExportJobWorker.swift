import Fluent
import Foundation
import SQLKit
import Vapor

/// Cross-process export worker. PostgreSQL claims are row-locked with
/// `SKIP LOCKED`; every state transition is additionally guarded by the lease
/// owner so a recovered stale worker cannot publish or overwrite an artifact.
actor ExportJobWorker: LifecycleHandler {
    private var loopTask: Task<Void, Never>?
    private var activeTask: Task<Void, Never>?
    private var activeJobID: UUID?
    private let workerID = UUID().uuidString.lowercased()
    private var nextPurgeAt = Date.distantPast

    nonisolated func didBoot(_ application: Application) throws {
        guard application.exportJobConfiguration.enabled else {
            application.logger.notice("[ExportWorker] Disabled by configuration.")
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
        let interval = UInt64(app.exportJobConfiguration.pollSeconds) * 1_000_000_000
        loopTask = Task { [weak self] in
            guard let self else { return }
            app.logger.notice("[ExportWorker] Durable export worker started.")
            while !Task.isCancelled {
                await self.tick(app: app)
                try? await Task.sleep(nanoseconds: interval)
            }
        }
    }

    private func stop() {
        loopTask?.cancel()
        activeTask?.cancel()
        loopTask = nil
        activeTask = nil
    }

    func requestCancellation(jobID: UUID) {
        guard activeJobID == jobID else { return }
        activeTask?.cancel()
    }

    private func tick(app: Application) async {
        if Date() >= nextPurgeAt {
            await Self.purgeExpired(app: app)
            nextPurgeAt = Date().addingTimeInterval(3_600)
        }
        guard activeTask == nil else { return }
        do {
            guard let job = try await Self.claimNext(
                on: app.db,
                workerID: workerID,
                now: Date(),
                leaseSeconds: app.exportJobConfiguration.leaseSeconds
            ), let jobID = job.id else { return }
            activeJobID = jobID
            activeTask = Task { [weak self] in
                await Self.execute(job: job, workerID: self?.workerID ?? "stopped", app: app)
                await self?.finished(jobID: jobID)
            }
        } catch {
            app.logger.error("[ExportWorker] Failed to claim an export job safely.")
        }
    }

    private func finished(jobID: UUID) {
        guard activeJobID == jobID else { return }
        activeJobID = nil
        activeTask = nil
    }

    @discardableResult
    static func processNext(
        app: Application,
        workerID: String,
        now: Date = Date()
    ) async throws -> UUID? {
        guard let job = try await claimNext(
            on: app.db,
            workerID: workerID,
            now: now,
            leaseSeconds: app.exportJobConfiguration.leaseSeconds
        ), let jobID = job.id else { return nil }
        await execute(job: job, workerID: workerID, app: app)
        return jobID
    }

    static func claimNext(
        on database: Database,
        workerID: String,
        now: Date,
        leaseSeconds: Int
    ) async throws -> ExportJob? {
        guard let sql = database as? SQLDatabase else { return nil }
        try await expireTerminalLeases(on: sql, now: now)
        let leaseExpiresAt = now.addingTimeInterval(TimeInterval(leaseSeconds))
        let rows: [any SQLRow]

        if sql.dialect.name.lowercased().contains("postgres") {
            rows = try await sql.raw("""
                WITH candidate AS (
                    SELECT id
                    FROM export_jobs
                    WHERE cancel_requested = FALSE
                      AND attempt_count < max_attempts
                      AND (
                        status = \(bind: ExportJobStatus.pending.rawValue)
                        OR (
                          status = \(bind: ExportJobStatus.processing.rawValue)
                          AND lease_expires_at IS NOT NULL
                          AND lease_expires_at <= \(bind: now)
                        )
                      )
                    ORDER BY created_at ASC, id ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE export_jobs AS job
                SET status = \(bind: ExportJobStatus.processing.rawValue),
                    attempt_count = job.attempt_count + 1,
                    lease_owner = \(bind: workerID),
                    lease_expires_at = \(bind: leaseExpiresAt),
                    started_at = COALESCE(job.started_at, \(bind: now)),
                    updated_at = \(bind: now)
                FROM candidate
                WHERE job.id = candidate.id
                RETURNING job.id
                """).all()
        } else {
            rows = try await sql.raw("""
                UPDATE export_jobs
                SET status = \(bind: ExportJobStatus.processing.rawValue),
                    attempt_count = attempt_count + 1,
                    lease_owner = \(bind: workerID),
                    lease_expires_at = \(bind: leaseExpiresAt),
                    started_at = COALESCE(started_at, \(bind: now)),
                    updated_at = \(bind: now)
                WHERE id = (
                    SELECT id
                    FROM export_jobs
                    WHERE cancel_requested = FALSE
                      AND attempt_count < max_attempts
                      AND (
                        status = \(bind: ExportJobStatus.pending.rawValue)
                        OR (
                          status = \(bind: ExportJobStatus.processing.rawValue)
                          AND lease_expires_at IS NOT NULL
                          AND lease_expires_at <= \(bind: now)
                        )
                      )
                    ORDER BY created_at ASC, id ASC
                    LIMIT 1
                )
                RETURNING id
                """).all()
        }

        guard let row = rows.first,
              let id = try? row.decode(column: "id", as: UUID.self) else { return nil }
        return try await ExportJob.find(id, on: database)
    }

    private static func execute(job: ExportJob, workerID: String, app: Application) async {
        guard let jobID = job.id,
              let format = job.format,
              let scan = try? await Scan.find(job.$scan.id, on: app.db),
              scan.$user.id == job.$user.id else {
            if let jobID = job.id {
                await finishFailure(
                    jobID: jobID,
                    workerID: workerID,
                    code: "invalid_job_reference",
                    app: app
                )
            }
            return
        }

        do {
            let built = try await ExportArtifactBuilder.build(
                jobID: jobID,
                scanID: job.$scan.id,
                format: format,
                app: app,
                configuration: app.exportJobConfiguration,
                progress: { completed, total in
                    try Task.checkCancellation()
                    guard try await heartbeat(
                        jobID: jobID,
                        workerID: workerID,
                        completed: completed,
                        total: total,
                        leaseSeconds: app.exportJobConfiguration.leaseSeconds,
                        on: app.db
                    ) else {
                        throw ExportArtifactBuilder.BuildError.cancelledOrLeaseLost
                    }
                }
            )
            try Task.checkCancellation()
            try job.setArtifact(built.data, manifest: built.manifest)
            guard let artifactCipher = job.artifactCipher,
                  let manifestCipher = job.manifestCipher else {
                throw ExportArtifactBuilder.BuildError.invalidJob
            }
            let completed = try await finishSuccess(
                jobID: jobID,
                workerID: workerID,
                artifactCipher: artifactCipher,
                manifestCipher: manifestCipher,
                resultCount: built.manifest.resultCount,
                retentionHours: app.exportJobConfiguration.retentionHours,
                on: app.db
            )
            if completed {
                await MetricsRegistry.shared.incExportJob(status: ExportJobStatus.completed.rawValue)
            } else {
                await finishCancelled(jobID: jobID, workerID: workerID, app: app)
            }
        } catch is CancellationError {
            await finishCancelled(jobID: jobID, workerID: workerID, app: app)
        } catch let failure as FieldCrypto.DecryptionFailure {
            await SensitiveFieldFailureReporter.report(failure, app: app, context: "export_job")
            await finishFailure(
                jobID: jobID,
                workerID: workerID,
                code: "encrypted_field_unavailable",
                app: app
            )
        } catch let error as ExportArtifactBuilder.BuildError {
            if error == .cancelledOrLeaseLost {
                await finishCancelled(jobID: jobID, workerID: workerID, app: app)
            } else {
                await finishFailure(
                    jobID: jobID,
                    workerID: workerID,
                    code: error.failureCode,
                    app: app
                )
            }
        } catch {
            await finishFailure(
                jobID: jobID,
                workerID: workerID,
                code: "export_internal",
                app: app
            )
        }
    }

    static func heartbeat(
        jobID: UUID,
        workerID: String,
        completed: Int,
        total: Int,
        leaseSeconds: Int,
        on database: Database
    ) async throws -> Bool {
        guard let sql = database as? SQLDatabase else { return false }
        let now = Date()
        let leaseExpiresAt = now.addingTimeInterval(TimeInterval(leaseSeconds))
        let rows = try await sql.raw("""
            UPDATE export_jobs
            SET progress_completed = \(bind: max(0, completed)),
                progress_total = \(bind: max(0, total)),
                lease_expires_at = \(bind: leaseExpiresAt),
                updated_at = \(bind: now)
            WHERE id = \(bind: jobID)
              AND status = \(bind: ExportJobStatus.processing.rawValue)
              AND lease_owner = \(bind: workerID)
              AND cancel_requested = FALSE
            RETURNING id
            """).all()
        return !rows.isEmpty
    }

    static func finishSuccess(
        jobID: UUID,
        workerID: String,
        artifactCipher: String,
        manifestCipher: String,
        resultCount: Int,
        retentionHours: Int,
        on database: Database
    ) async throws -> Bool {
        guard let sql = database as? SQLDatabase else { return false }
        let now = Date()
        let expiresAt = now.addingTimeInterval(TimeInterval(retentionHours * 3_600))
        let rows = try await sql.raw("""
            UPDATE export_jobs
            SET status = \(bind: ExportJobStatus.completed.rawValue),
                progress_completed = \(bind: resultCount),
                progress_total = \(bind: resultCount),
                artifact = \(bind: artifactCipher),
                manifest = \(bind: manifestCipher),
                failure_code = NULL,
                lease_owner = NULL,
                lease_expires_at = NULL,
                completed_at = \(bind: now),
                expires_at = \(bind: expiresAt),
                updated_at = \(bind: now)
            WHERE id = \(bind: jobID)
              AND status = \(bind: ExportJobStatus.processing.rawValue)
              AND lease_owner = \(bind: workerID)
              AND cancel_requested = FALSE
            RETURNING id
            """).all()
        return !rows.isEmpty
    }

    private static func finishFailure(
        jobID: UUID,
        workerID: String,
        code: String,
        app: Application
    ) async {
        guard let sql = app.db as? SQLDatabase else { return }
        let now = Date()
        do {
            let rows = try await sql.raw("""
                UPDATE export_jobs
                SET status = \(bind: ExportJobStatus.failed.rawValue),
                    artifact = NULL,
                    manifest = NULL,
                    failure_code = \(bind: code),
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    completed_at = \(bind: now),
                    updated_at = \(bind: now)
                WHERE id = \(bind: jobID)
                  AND status = \(bind: ExportJobStatus.processing.rawValue)
                  AND lease_owner = \(bind: workerID)
                RETURNING id
                """).all()
            if !rows.isEmpty {
                await MetricsRegistry.shared.incExportJob(status: ExportJobStatus.failed.rawValue)
            }
        } catch {
            app.logger.error("[ExportWorker] Failed to persist a bounded export failure.")
        }
    }

    private static func finishCancelled(
        jobID: UUID,
        workerID: String,
        app: Application
    ) async {
        guard let sql = app.db as? SQLDatabase else { return }
        let now = Date()
        do {
            let rows = try await sql.raw("""
                UPDATE export_jobs
                SET status = \(bind: ExportJobStatus.cancelled.rawValue),
                    cancel_requested = TRUE,
                    artifact = NULL,
                    manifest = NULL,
                    failure_code = NULL,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    completed_at = \(bind: now),
                    updated_at = \(bind: now)
                WHERE id = \(bind: jobID)
                  AND status = \(bind: ExportJobStatus.processing.rawValue)
                  AND lease_owner = \(bind: workerID)
                RETURNING id
                """).all()
            if !rows.isEmpty {
                await MetricsRegistry.shared.incExportJob(status: ExportJobStatus.cancelled.rawValue)
            }
        } catch {
            app.logger.error("[ExportWorker] Failed to persist export cancellation.")
        }
    }

    private static func expireTerminalLeases(on sql: SQLDatabase, now: Date) async throws {
        try await sql.raw("""
            UPDATE export_jobs
            SET status = \(bind: ExportJobStatus.cancelled.rawValue),
                artifact = NULL,
                manifest = NULL,
                failure_code = NULL,
                lease_owner = NULL,
                lease_expires_at = NULL,
                completed_at = \(bind: now),
                updated_at = \(bind: now)
            WHERE id IN (
                SELECT id FROM export_jobs
                WHERE status = \(bind: ExportJobStatus.processing.rawValue)
                  AND cancel_requested = TRUE
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= \(bind: now)
                ORDER BY lease_expires_at ASC, id ASC
                LIMIT 100
            )
            """).run()
        try await sql.raw("""
            UPDATE export_jobs
            SET status = \(bind: ExportJobStatus.failed.rawValue),
                artifact = NULL,
                manifest = NULL,
                failure_code = \(bind: "worker_interrupted"),
                lease_owner = NULL,
                lease_expires_at = NULL,
                completed_at = \(bind: now),
                updated_at = \(bind: now)
            WHERE id IN (
                SELECT id FROM export_jobs
                WHERE status = \(bind: ExportJobStatus.processing.rawValue)
                  AND cancel_requested = FALSE
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= \(bind: now)
                  AND attempt_count >= max_attempts
                ORDER BY lease_expires_at ASC, id ASC
                LIMIT 100
            )
            """).run()
    }

    private static func purgeExpired(app: Application) async {
        guard let sql = app.db as? SQLDatabase else { return }
        let now = Date()
        do {
            try await sql.raw("""
                DELETE FROM export_jobs
                WHERE id IN (
                    SELECT id FROM export_jobs
                    WHERE expires_at <= \(bind: now)
                      AND status IN (
                        \(bind: ExportJobStatus.completed.rawValue),
                        \(bind: ExportJobStatus.failed.rawValue),
                        \(bind: ExportJobStatus.cancelled.rawValue)
                      )
                    ORDER BY expires_at ASC, id ASC
                    LIMIT 100
                )
                """).run()
        } catch {
            app.logger.error("[ExportWorker] Expired-artifact retention sweep failed.")
        }
    }
}

private struct ExportJobWorkerKey: StorageKey {
    typealias Value = ExportJobWorker
}

extension Application {
    var exportJobWorker: ExportJobWorker {
        if let existing = storage[ExportJobWorkerKey.self] { return existing }
        let worker = ExportJobWorker()
        storage[ExportJobWorkerKey.self] = worker
        return worker
    }
}
