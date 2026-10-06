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
        guard let user = try await req.currentUser(), let userID = user.id else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }
        return try await pagedSummaries(req: req, maskInputs: false) {
            Scan.query(on: req.db).filter(\.$user.$id == userID)
        }
    }

    @Sendable
    func adminScans(req: Request) async throws -> PagedScans {
        let user = try await req.requireRecentSessionUser()
        guard user.isAdmin else {
            throw Abort(.forbidden, reason: "Admin access required.")
        }
        return try await pagedSummaries(req: req, maskInputs: true) {
            Scan.query(on: req.db)
        }
    }

    /// One pagination and summary path for both lists. They were two copies of
    /// the same fifty lines, and both fetched each listed scan's results with a
    /// query of its own — a round trip per row, every column of every result.
    private func pagedSummaries(
        req: Request,
        maskInputs: Bool,
        scans: () -> QueryBuilder<Scan>
    ) async throws -> PagedScans {
        let page   = max(1, (try? req.query.get(Int.self, at: "page"))  ?? 1)
        let limit  = max(1, min(100, (try? req.query.get(Int.self, at: "limit")) ?? 20))
        let q      = try? req.query.get(String.self, at: "q")
        let offset = (page - 1) * limit

        // DB-level pagination — never load a full scan history into memory. The
        // search path still matches substrings in Swift (case-insensitive across
        // DB dialects), bounded to a 500-row candidate window.
        let total: Int
        let paged: [Scan]
        if let q, !q.isEmpty {
            let candidates = try await scans()
                .sort(\.$createdAt, .descending)
                .range(..<500)
                .all()
            let matched = try candidates.filter { try $0.input.localizedCaseInsensitiveContains(q) }
            total = matched.count
            paged = Array(matched.dropFirst(offset).prefix(limit))
        } else {
            total = try await scans().count()
            paged = try await scans()
                .sort(\.$createdAt, .descending)
                .range(offset..<(offset + limit))
                .all()
        }
        let pages = max(1, Int(ceil(Double(total) / Double(limit))))

        // Every listed scan's results in one query, grouped here.
        let scanIDs = paged.compactMap(\.id)
        let resultsByScan: [UUID: [Result]] = scanIDs.isEmpty ? [:] : Dictionary(
            grouping: try await Result.query(on: req.db).filter(\.$scan.$id ~~ scanIDs).all(),
            by: { $0.$scan.id }
        )

        let items: [ScanSummary] = try paged.compactMap { scan in
            guard let scanID = scan.id else { return nil }
            let scanResults = resultsByScan[scanID] ?? []
            let risk = try RiskScorer.compute(results: scanResults)
            let input = try scan.input
            return ScanSummary(
                scanID: scanID,
                input: maskInputs ? maskInput(input) : input,
                status: scan.status.rawValue,
                resultCount: scanResults.count,
                riskScore: risk.value,
                riskLevel: risk.level.rawValue,
                createdAt: scan.createdAt.map { $0.timeIntervalSince1970 },
                completedAt: scan.completedAt.map { $0.timeIntervalSince1970 }
            )
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
