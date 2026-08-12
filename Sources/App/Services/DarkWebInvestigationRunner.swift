import Fluent
import Foundation
import Vapor

/// Polls the durable queue and dispatches at most one dark-web investigation at
/// a time. Resource ceilings live in the worker's systemd unit; this actor adds
/// application-level serialization and cancellation.
actor DarkWebInvestigationRunner: LifecycleHandler {
    private var loopTask: Task<Void, Never>?
    private var activeJobID: UUID?
    private var activeTask: Task<Void, Never>?

    nonisolated func didBoot(_ application: Application) throws {
        guard application.darkWebConfiguration.enabled else {
            application.logger.notice("[DarkWeb] Worker integration disabled.")
            return
        }
        let app = application
        Task { await self.start(app: app) }
    }

    private func start(app: Application) {
        guard loopTask == nil else { return }
        loopTask = Task { [weak self] in
            guard let self else { return }
            await self.recoverInterruptedJobs(app: app)
            while !Task.isCancelled {
                await self.tick(app: app)
                try? await Task.sleep(nanoseconds: 2 * 1_000_000_000)
            }
        }
    }

    nonisolated func shutdown(_ application: Application) {
        Task { await self.stop() }
    }

    private func stop() {
        loopTask?.cancel()
        activeTask?.cancel()
        loopTask = nil
    }

    func requestCancellation(jobID: UUID, app: Application) async {
        guard activeJobID == jobID else { return }
        // The HTTP task cancellation alone only closes the loopback connection;
        // explicitly tell the worker to kill the child process group first.
        try? await DarkWebWorkerClient.cancel(
            jobID: jobID, configuration: app.darkWebConfiguration, on: app
        )
        activeTask?.cancel()
    }

    private func recoverInterruptedJobs(app: Application) async {
        let jobs = (try? await DarkWebInvestigation.query(on: app.db)
            .filter(\.$statusRaw == DarkWebInvestigationStatus.running.rawValue)
            .all()) ?? []
        for job in jobs {
            job.status = job.cancelRequested ? .cancelled : .failed
            job.failureCode = job.cancelRequested ? nil : "worker_interrupted"
            job.completedAt = Date()
            job.leaseExpiresAt = nil
            try? await job.save(on: app.db)
        }
    }

    private func tick(app: Application) async {
        await purgeExpired(app: app)
        guard activeTask == nil else { return }

        guard let job = try? await DarkWebInvestigation.query(on: app.db)
            .filter(\.$statusRaw == DarkWebInvestigationStatus.pending.rawValue)
            .sort(\.$createdAt, .ascending)
            .first(),
              let jobID = job.id else { return }

        if job.cancelRequested {
            job.status = .cancelled
            job.completedAt = Date()
            try? await job.save(on: app.db)
            return
        }

        job.status = .running
        job.startedAt = Date()
        job.attemptCount += 1
        job.leaseExpiresAt = Date().addingTimeInterval(
            TimeInterval(app.darkWebConfiguration.jobTimeoutSeconds + 30)
        )
        do { try await job.save(on: app.db) }
        catch {
            app.logger.error("[DarkWeb] Failed to lease queued job.")
            return
        }

        activeJobID = jobID
        activeTask = Task { [weak self] in
            await Self.execute(jobID: jobID, app: app)
            await self?.finished(jobID: jobID)
        }
    }

    private func finished(jobID: UUID) {
        guard activeJobID == jobID else { return }
        activeTask = nil
        activeJobID = nil
    }

    private static func execute(jobID: UUID, app: Application) async {
        guard let job = try? await DarkWebInvestigation.find(jobID, on: app.db) else { return }

        do {
            let result = try await DarkWebWorkerClient.execute(
                jobID: jobID,
                target: job.target,
                targetKind: job.targetKind,
                configuration: app.darkWebConfiguration,
                on: app
            )
            guard !Task.isCancelled else { throw CancellationError() }

            let latest = try await DarkWebInvestigation.find(jobID, on: app.db)
            guard let latest else { return }
            if latest.cancelRequested {
                latest.status = .cancelled
                latest.resultJSON = nil
                latest.resultCount = 0
            } else {
                latest.status = .completed
                latest.resultJSON = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
                latest.resultCount = result.findings.count
                latest.failureCode = nil
            }
            latest.completedAt = Date()
            latest.leaseExpiresAt = nil
            try await latest.save(on: app.db)
            await MetricsRegistry.shared.incDarkWebJob(status: latest.status.rawValue)
        } catch is CancellationError {
            await finishFailure(jobID: jobID, code: nil, cancelled: true, app: app)
        } catch let error as DarkWebWorkerClient.ClientError {
            await finishFailure(jobID: jobID, code: error.failureCode, cancelled: false, app: app)
        } catch {
            await finishFailure(jobID: jobID, code: "worker_internal", cancelled: false, app: app)
        }
    }

    private static func finishFailure(
        jobID: UUID,
        code: String?,
        cancelled: Bool,
        app: Application
    ) async {
        guard let job = try? await DarkWebInvestigation.find(jobID, on: app.db) else { return }
        job.status = (cancelled || job.cancelRequested) ? .cancelled : .failed
        job.failureCode = job.status == .failed ? code : nil
        job.resultJSON = nil
        job.resultCount = 0
        job.completedAt = Date()
        job.leaseExpiresAt = nil
        try? await job.save(on: app.db)
        await MetricsRegistry.shared.incDarkWebJob(status: job.status.rawValue)
    }

    private func purgeExpired(app: Application) async {
        let now = Date()
        let expired = (try? await DarkWebInvestigation.query(on: app.db)
            .filter(\.$expiresAt <= now)
            .limit(100)
            .all()) ?? []
        for job in expired where job.id != activeJobID {
            try? await job.delete(on: app.db)
        }
    }
}

private struct DarkWebRunnerKey: StorageKey {
    typealias Value = DarkWebInvestigationRunner
}

extension Application {
    var darkWebRunner: DarkWebInvestigationRunner {
        if let existing = storage[DarkWebRunnerKey.self] { return existing }
        let runner = DarkWebInvestigationRunner()
        storage[DarkWebRunnerKey.self] = runner
        return runner
    }
}
