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
                // Retention sweep — must run per-user with each user's effective
                // policy. The previous version ran a hard 30-day global delete
                // FIRST, which would silently destroy scans of users who had
                // configured 90- or 365-day retention before their per-user
                // loop got a chance to apply.
                //
                // New flow:
                //   1. Anonymous scans (no owner) — default 30 days.
                //   2. Each user — effective retention = user.retentionDays ?? 30.
                let now = Date()
                let defaultCutoff = now.addingTimeInterval(-30 * 86400)

                do {
                    try await Scan.query(on: db)
                        .filter(\.$user.$id == nil)
                        .filter(\.$createdAt < defaultCutoff)
                        .delete()
                } catch {
                    app.logger.error("CleanupJob: anonymous scan cleanup failed: \(error)")
                }

                let allUsers = (try? await User.query(on: db).all()) ?? []
                for user in allUsers {
                    guard let userID = user.id else { continue }
                    let days = user.retentionDays ?? 30
                    guard days > 0 else { continue }
                    let userCutoff = now.addingTimeInterval(-Double(days) * 86400)
                    do {
                        try await Scan.query(on: db)
                            .filter(\.$user.$id == userID)
                            .filter(\.$createdAt < userCutoff)
                            .delete()
                    } catch {
                        app.logger.error("CleanupJob: cleanup for user \(user.username) failed: \(error)")
                    }
                }
                app.logger.info("CleanupJob: completed retention sweep across \(allUsers.count) user(s)")

                // Audit-log retention — keep ≤ 90 days. Without this the
                // audit_logs table grows forever; admins eventually face an
                // unusable log list and an oversized backup.
                let auditCutoff = now.addingTimeInterval(-90 * 86400)
                do {
                    try await AuditLog.query(on: db)
                        .filter(\.$createdAt < auditCutoff)
                        .delete()
                } catch {
                    app.logger.error("CleanupJob: audit log cleanup failed: \(error)")
                }

                // Plugin cache — drop entries past their TTL. The indexed
                // expires_at column makes this an O(log n) range delete.
                do {
                    try await PluginCacheEntry.query(on: db)
                        .filter(\.$expiresAt < now)
                        .delete()
                } catch {
                    app.logger.error("CleanupJob: plugin cache cleanup failed: \(error)")
                }
            }
        }
    }
}
