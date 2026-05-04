import Vapor
import Fluent
import SQLKit

struct StatsResponse: Content {
    struct SourceStat: Content {
        let source: String
        let hitCount: Int
    }
    let totalScans: Int
    let scansLast24h: Int
    let scansLast7d: Int
    let totalResults: Int
    let topSources: [SourceStat]
    let recentTargets: [String]   // masked inputs for recent scans
}

struct StatsController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.grouped(ScanRateLimiter(anonMax: 30, authedMax: 60, windowSeconds: 60)).get("stats", use: getStats)
    }

    @Sendable
    func getStats(req: Request) async throws -> StatsResponse {
        let db = req.db

        // Total scans
        let totalScans = try await Scan.query(on: db).count()

        // Scans in last 24h
        let since24h = Date().addingTimeInterval(-86_400)
        let scansLast24h = try await Scan.query(on: db)
            .filter(\.$createdAt >= since24h)
            .count()

        // Scans in last 7d
        let since7d = Date().addingTimeInterval(-7 * 86_400)
        let scansLast7d = try await Scan.query(on: db)
            .filter(\.$createdAt >= since7d)
            .count()

        // Total results
        let totalResults = try await Result.query(on: db).count()

        // Top 10 sources by hit count (raw SQL for GROUP BY + ORDER BY)
        var topSources: [StatsResponse.SourceStat] = []
        if let sqlDB = db as? SQLDatabase {
            struct Row: Decodable { let source: String; let hit_count: Int }
            let rows = try await sqlDB.raw("""
                SELECT source, COUNT(*) AS hit_count
                FROM results
                GROUP BY source
                ORDER BY hit_count DESC
                LIMIT 10
                """).all(decoding: Row.self)
            topSources = rows.map { StatsResponse.SourceStat(source: $0.source, hitCount: $0.hit_count) }
        }

        // 10 most recent scans — mask PII before sending to client
        let recentScans = try await Scan.query(on: db)
            .sort(\.$createdAt, .descending)
            .limit(10)
            .all()
        let recentTargets = recentScans.map { maskInput($0.input) }

        return StatsResponse(
            totalScans: totalScans,
            scansLast24h: scansLast24h,
            scansLast7d: scansLast7d,
            totalResults: totalResults,
            topSources: topSources,
            recentTargets: recentTargets
        )
    }

    /// Mask PII: show only domain part for emails, first 3 chars + *** for usernames.
    private func maskInput(_ input: String) -> String {
        if let atIdx = input.firstIndex(of: "@") {
            return "***@" + String(input[input.index(after: atIdx)...])
        }
        return String(input.prefix(3)) + "***"
    }
}
