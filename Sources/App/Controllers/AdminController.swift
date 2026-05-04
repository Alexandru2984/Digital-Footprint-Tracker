import Vapor
import Fluent

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

        // Top plugins — aggregate in Swift so this works with any DB backend
        let allResults = try await Result.query(on: db).all()
        var sourceCounts: [String: Int] = [:]
        for r in allResults {
            sourceCounts[r.source, default: 0] += 1
        }
        let topPlugins: [DashboardResponse.PluginStat] = sourceCounts
            .sorted { $0.value > $1.value }
            .prefix(10)
            .map { DashboardResponse.PluginStat(source: $0.key, hitCount: $0.value) }

        return DashboardResponse(
            totalScans: totalScans,
            totalUsers: totalUsers,
            totalResults: totalResults,
            scansPerDay: scansPerDay,
            topPlugins: topPlugins
        )
    }
}
