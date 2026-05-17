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

struct AdminController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.get("admin", "dashboard", use: dashboard)
        noCache.get("admin", "audit", use: auditLog)
    }

    @Sendable
    func dashboard(req: Request) async throws -> DashboardResponse {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }
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
    func auditLog(req: Request) async throws -> Page<AuditLog> {
        guard let user = try await req.currentUser(), user.isAdmin else {
            throw Abort(.forbidden)
        }
        return try await AuditLog.query(on: req.db)
            .sort(\.$createdAt, .descending)
            .paginate(for: req)
    }
}
