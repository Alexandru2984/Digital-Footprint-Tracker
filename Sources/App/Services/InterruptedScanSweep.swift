import Fluent
import Vapor

/// Scans run inside this process, so a scan still `pending` when the process
/// starts was interrupted (a restart, a deploy, a crash) and will never finish.
/// Without this it said "pending" forever, and anything polling it waited
/// forever too. Marked failed at boot; whatever it found before stopping was
/// persisted as it arrived and stays.
struct InterruptedScanSweep: LifecycleHandler {
    func didBoot(_ app: Application) throws {
        let bootedAt = Date()
        Task {
            guard let db = app.databases.database(nil, logger: app.logger, on: app.eventLoopGroup.any()) else { return }
            do {
                let count = try await Self.sweep(on: db, startedBefore: bootedAt)
                if count > 0 { app.logger.notice("Marked \(count) scan(s) interrupted by the restart as failed") }
            } catch {
                app.logger.error("Interrupted-scan sweep failed: \(error)")
            }
        }
    }

    /// Marks scans still pending that started before `startedBefore` as
    /// failed; returns how many.
    @discardableResult
    static func sweep(on db: Database, startedBefore: Date) async throws -> Int {
        let stuck = try await Scan.query(on: db)
            .filter(\.$statusRaw == ScanStatus.pending.rawValue)
            .filter(\.$createdAt < startedBefore)
            .all()
        for scan in stuck {
            scan.status = .failed
            scan.completedAt = Date()
            try await scan.save(on: db)
        }
        return stuck.count
    }
}
