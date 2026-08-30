import Vapor
import Fluent

struct ScanSummary: Content {
    let scanID: UUID?
    let input: String
    let status: String
    let resultCount: Int
    let riskScore: Int
    let riskLevel: String
    let createdAt: Double?
    let completedAt: Double?
}

struct PagedScans: Content {
    let items: [ScanSummary]
    let total: Int
    let page: Int
    let pages: Int
}

struct UserController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.get("my-scans", use: myScans)
        // This route lives here rather than in AdminController, which is exactly
        // why the admin gate is a middleware and not just a habit.
        noCache.grouped(AdminMiddleware()).get("admin", "scans", use: adminScans)
    }

    @Sendable
    func myScans(req: Request) async throws -> PagedScans {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }

        let page  = max(1, (try? req.query.get(Int.self, at: "page"))  ?? 1)
        let limit = max(1, min(100, (try? req.query.get(Int.self, at: "limit")) ?? 20))
        let q     = try? req.query.get(String.self, at: "q")

        // DB-level pagination — never load the user's full scan history into
        // memory. For the search path we still need Swift-side substring
        // filtering (case-insensitive across DB dialects), but bounded to a
        // 500-row candidate window to avoid OOM on huge histories.
        let total: Int
        let paged: [Scan]
        if let q = q, !q.isEmpty {
            let candidates = try await Scan.query(on: req.db)
                .filter(\.$user.$id == user.id!)
                .sort(\.$createdAt, .descending)
                .range(..<500)
                .all()
            let matched = try candidates.filter { try $0.input.localizedCaseInsensitiveContains(q) }
            total = matched.count
            let offset = (page - 1) * limit
            paged = Array(matched.dropFirst(offset).prefix(limit))
        } else {
            total = try await Scan.query(on: req.db)
                .filter(\.$user.$id == user.id!)
                .count()
            let offset = (page - 1) * limit
            paged = try await Scan.query(on: req.db)
                .filter(\.$user.$id == user.id!)
                .sort(\.$createdAt, .descending)
                .range(offset..<(offset + limit))
                .all()
        }
        let pages = max(1, Int(ceil(Double(total) / Double(limit))))

        var items: [ScanSummary] = []
        for scan in paged {
            guard let scanID = scan.id else { continue }
            let scanResults = try await Result.query(on: req.db)
                .filter(\Result.$scan.$id == scanID)
                .all()
            let risk = try RiskScorer.compute(results: scanResults)
            items.append(ScanSummary(
                scanID: scanID,
                input: try scan.input,
                status: scan.status.rawValue,
                resultCount: scanResults.count,
                riskScore: risk.value,
                riskLevel: risk.level.rawValue,
                createdAt: scan.createdAt.map { $0.timeIntervalSince1970 },
                completedAt: scan.completedAt.map { $0.timeIntervalSince1970 }
            ))
        }

        return PagedScans(items: items, total: total, page: page, pages: pages)
    }

    @Sendable
    func adminScans(req: Request) async throws -> PagedScans {
        let user = try await req.requireRecentSessionUser()
        guard user.isAdmin else {
            throw Abort(.forbidden, reason: "Admin access required.")
        }

        let page  = max(1, (try? req.query.get(Int.self, at: "page"))  ?? 1)
        let limit = max(1, min(100, (try? req.query.get(Int.self, at: "limit")) ?? 20))
        let q     = try? req.query.get(String.self, at: "q")

        // DB-level pagination across all users. Search path still does
        // Swift-side substring matching but capped at 500 candidates.
        let total: Int
        let paged: [Scan]
        if let q = q, !q.isEmpty {
            let candidates = try await Scan.query(on: req.db)
                .sort(\.$createdAt, .descending)
                .range(..<500)
                .all()
            let matched = try candidates.filter { try $0.input.localizedCaseInsensitiveContains(q) }
            total = matched.count
            let offset = (page - 1) * limit
            paged = Array(matched.dropFirst(offset).prefix(limit))
        } else {
            total = try await Scan.query(on: req.db).count()
            let offset = (page - 1) * limit
            paged = try await Scan.query(on: req.db)
                .sort(\.$createdAt, .descending)
                .range(offset..<(offset + limit))
                .all()
        }
        let pages = max(1, Int(ceil(Double(total) / Double(limit))))

        var items: [ScanSummary] = []
        for scan in paged {
            guard let scanID = scan.id else { continue }
            let scanResults = try await Result.query(on: req.db)
                .filter(\Result.$scan.$id == scanID)
                .all()
            let risk = try RiskScorer.compute(results: scanResults)
            items.append(ScanSummary(
                scanID: scanID,
                input: maskInput(try scan.input),
                status: scan.status.rawValue,
                resultCount: scanResults.count,
                riskScore: risk.value,
                riskLevel: risk.level.rawValue,
                createdAt: scan.createdAt.map { $0.timeIntervalSince1970 },
                completedAt: scan.completedAt.map { $0.timeIntervalSince1970 }
            ))
        }

        return PagedScans(items: items, total: total, page: page, pages: pages)
    }

    private func maskInput(_ input: String) -> String {
        if let atIdx = input.firstIndex(of: "@") {
            return "*@" + String(input[input.index(after: atIdx)...])
        } else if input.count > 3 {
            return String(input.prefix(3)) + "***"
        } else {
            return "***"
        }
    }
}
