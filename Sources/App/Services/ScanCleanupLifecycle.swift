import Vapor
import Fluent

/// Deletes scans (and their results via cascade) older than 30 days.
/// Runs once per day in a detached background task for the lifetime of the app.
struct ScanCleanupLifecycle: LifecycleHandler {
    private let interval: Duration

    init(interval: Duration = .seconds(86400)) {
        self.interval = interval
    }

    func didBoot(_ app: Application) throws {
        let cleanupInterval = interval
        Task.detached(priority: .background) {
            while !Task.isCancelled {
                try? await Task.sleep(for: cleanupInterval)
                guard !Task.isCancelled else { break }
                guard let db = app.databases.database(
                    nil, logger: app.logger, on: app.eventLoopGroup.any()
                ) else { continue }
                let cutoff = Calendar.current.date(byAdding: .day, value: -30, to: Date()) ?? Date()
                do {
                    try await Scan.query(on: db)
                        .filter(\.$createdAt < cutoff)
                        .delete()
                    app.logger.info("CleanupJob: pruned scans older than 30 days")
                } catch {
                    app.logger.error("CleanupJob failed: \(error)")
                }
            }
        }
    }
}
