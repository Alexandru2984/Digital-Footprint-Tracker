import Vapor
import Fluent
import SQLKit

struct DashboardResponse: Content {
    struct DayCount: Content {
        let date: String
        let count: Int
    }
    struct PluginStat: Content {
        let source: String
        let hitCount: Int
    }
    let totalScans: Int
    let totalUsers: Int
    let totalResults: Int
    let scansPerDay: [DayCount]
    let topPlugins: [PluginStat]
}

struct AuditLogDTO: Content {
    let id: UUID?
    let userID: UUID?
    let action: String
    let target: String
    let ip: String
    let createdAt: Date?

    init(_ entry: AuditLog) throws {
        id = entry.id
        userID = entry.userID
        action = entry.action
        target = try entry.target
        ip = try entry.ip
        createdAt = entry.createdAt
    }
}

struct NotificationDeliveryJobDTO: Content {
    let id: UUID?
    let eventID: UUID
    let channel: String
    let status: String
    let attemptCount: Int
    let maxAttempts: Int
    let nextAttemptAt: Date
    let lastFailureCode: String?
    let createdAt: Date?
    let updatedAt: Date?
    let completedAt: Date?

    init(_ job: NotificationDeliveryJob) {
        id = job.id
        eventID = job.$event.id
        channel = job.channelRaw
        status = job.statusRaw
        attemptCount = job.attemptCount
        maxAttempts = job.maxAttempts
        nextAttemptAt = job.nextAttemptAt
        lastFailureCode = job.lastFailureCode
        createdAt = job.createdAt
        updatedAt = job.updatedAt
        completedAt = job.completedAt
    }
}

struct AdminController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        // AdminMiddleware is the structural guarantee; the per-handler checks
        // below remain as an independent one. See AdminMiddleware.
        let noCache = routes.grouped(NoCacheMiddleware()).grouped(AdminMiddleware())
        noCache.get("admin", "dashboard", use: dashboard)
        noCache.get("admin", "audit", use: auditLog)
        noCache.get("admin", "audit", "integrity", use: auditIntegrity)
        noCache.get("admin", "notification-deliveries", use: notificationDeliveries)
        noCache.post("admin", "notification-deliveries", ":id", "retry", use: retryNotificationDelivery)
    }

    @Sendable
    func dashboard(req: Request) async throws -> DashboardResponse {
        let user = try await req.requireRecentSessionUser()
        guard user.isAdmin else {
            throw Abort(.forbidden, reason: "Admin access required.")
        }

        let db = req.db

        let totalScans   = try await Scan.query(on: db).count()
        let totalUsers   = try await User.query(on: db).count()
        let totalResults = try await Result.query(on: db).count()

        // Scans per day for last 14 days (Swift-side grouping, works with SQLite + Postgres)
        let since14d = Date().addingTimeInterval(-14 * 86_400)
        let recentScans = try await Scan.query(on: db)
            .filter(\.$createdAt >= since14d)
            .all()

        let calendar = Calendar(identifier: .gregorian)
        var countsByDay: [String: Int] = [:]
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        for scan in recentScans {
            if let ca = scan.createdAt {
                let dayStart = calendar.startOfDay(for: ca)
                let key = formatter.string(from: dayStart)
                countsByDay[key, default: 0] += 1
            }
        }
        // Fill in missing days with 0 so the chart has a complete 14-day window
        var scansPerDay: [DashboardResponse.DayCount] = []
        for dayOffset in (0..<14).reversed() {
            let day = calendar.date(byAdding: .day, value: -dayOffset, to: calendar.startOfDay(for: Date()))!
            let key = formatter.string(from: day)
            scansPerDay.append(.init(date: key, count: countsByDay[key] ?? 0))
        }

        // Top plugins — push the aggregation into the database (GROUP BY +
        // ORDER BY + LIMIT). The previous version loaded every Result row
        // into memory just to count occurrences per source — OOM-prone on
        // any non-trivial dataset. Matches StatsController.getStats pattern.
        var topPlugins: [DashboardResponse.PluginStat] = []
        if let sqlDB = db as? SQLDatabase {
            struct Row: Decodable { let source: String; let hit_count: Int }
            let rows = try await sqlDB.raw("""
                SELECT source, COUNT(*) AS hit_count
                FROM results
                GROUP BY source
                ORDER BY hit_count DESC
                LIMIT 10
                """).all(decoding: Row.self)
            topPlugins = rows.map { DashboardResponse.PluginStat(source: $0.source, hitCount: $0.hit_count) }
        }

        return DashboardResponse(
            totalScans: totalScans,
            totalUsers: totalUsers,
            totalResults: totalResults,
            scansPerDay: scansPerDay,
            topPlugins: topPlugins
        )
    }

    @Sendable
    func auditLog(req: Request) async throws -> Page<AuditLogDTO> {
        let user = try await req.requireRecentSessionUser()
        guard user.isAdmin else {
            throw Abort(.forbidden)
        }
        let page = try await AuditLog.query(on: req.db)
            .sort(\.$createdAt, .descending)
            .paginate(for: req)
        return Page(items: try page.items.map(AuditLogDTO.init), metadata: page.metadata)
    }

    @Sendable
    func auditIntegrity(req: Request) async throws -> AuditIntegrityVerification {
        let user = try await req.requireRecentSessionUser()
        guard user.isAdmin else {
            throw Abort(.forbidden, reason: "Admin access required.")
        }
        guard let configuration = req.application.auditIntegrityConfiguration else {
            throw Abort(.serviceUnavailable, reason: "Signed audit integrity is not configured.")
        }
        let result = try await AuditIntegrityLedger.verify(
            on: req.db,
            configuration: configuration
        )
        await MetricsRegistry.shared.recordAuditIntegrityVerification(result)
        if !result.isValid {
            req.logger.critical(
                "Audit integrity verification failed (code=\(result.failureCode ?? "unknown"))."
            )
        }
        return result
    }

    @Sendable
    func notificationDeliveries(req: Request) async throws -> [NotificationDeliveryJobDTO] {
        let user = try await req.requireRecentSessionUser()
        guard user.isAdmin else { throw Abort(.forbidden, reason: "Admin access required.") }

        let rawStatus = (try? req.query.get(String.self, at: "status"))
            ?? NotificationDeliveryJobStatus.deadLetter.rawValue
        guard let status = NotificationDeliveryJobStatus(rawValue: rawStatus) else {
            throw Abort(.badRequest, reason: "Unknown notification delivery status.")
        }
        let requestedLimit = (try? req.query.get(Int.self, at: "limit")) ?? 50
        guard (1...100).contains(requestedLimit) else {
            throw Abort(.badRequest, reason: "limit must be between 1 and 100.")
        }

        let jobs = try await NotificationDeliveryJob.query(on: req.db)
            .filter(\.$statusRaw == status.rawValue)
            .sort(\.$updatedAt, .descending)
            .limit(requestedLimit)
            .all()
        return jobs.map(NotificationDeliveryJobDTO.init)
    }

    @Sendable
    func retryNotificationDelivery(req: Request) async throws -> HTTPStatus {
        let user = try await req.requireRecentSessionUser()
        guard user.isAdmin else { throw Abort(.forbidden, reason: "Admin access required.") }
        guard let id = req.parameters.get("id", as: UUID.self),
              let job = try await NotificationDeliveryJob.find(id, on: req.db) else {
            throw Abort(.notFound)
        }
        guard job.status == .deadLetter else {
            throw Abort(.conflict, reason: "Only dead-letter deliveries can be retried.")
        }

        guard let sql = req.db as? SQLDatabase else {
            throw Abort(.internalServerError, reason: "Notification delivery database is unavailable.")
        }
        let now = Date()
        let replayedRows = try await sql.raw("""
            UPDATE notification_delivery_jobs
            SET status = \(bind: NotificationDeliveryJobStatus.pending.rawValue),
                attempt_count = 0,
                next_attempt_at = \(bind: now),
                lease_owner = NULL,
                lease_expires_at = NULL,
                last_failure_code = NULL,
                completed_at = NULL,
                updated_at = \(bind: now)
            WHERE id = \(bind: id)
              AND status = \(bind: NotificationDeliveryJobStatus.deadLetter.rawValue)
            RETURNING id
            """).all()
        guard !replayedRows.isEmpty else {
            // Another administrator may have replayed this row after our read.
            // Never overwrite a lease acquired in that interval.
            throw Abort(.conflict, reason: "Delivery was already replayed.")
        }
        await AuditLogger.log(
            req: req,
            action: "retry_notification_delivery",
            target: id.uuidString.lowercased()
        )
        return .accepted
    }
}
