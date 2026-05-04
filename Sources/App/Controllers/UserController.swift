import Vapor
import Fluent

struct ScanSummary: Content {
    let scanID: UUID?
    let input: String
    let status: String
    let resultCount: Int
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
        noCache.get("admin", "scans", use: adminScans)
    }

    @Sendable
    func myScans(req: Request) async throws -> PagedScans {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }

        let page  = max(1, (try? req.query.get(Int.self, at: "page"))  ?? 1)
        let limit = max(1, min(100, (try? req.query.get(Int.self, at: "limit")) ?? 20))
        let q     = try? req.query.get(String.self, at: "q")

        var scans = try await Scan.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .sort(\.$createdAt, .descending)
            .all()

        if let q = q, !q.isEmpty {
            scans = scans.filter { $0.input.localizedCaseInsensitiveContains(q) }
        }

        let total  = scans.count
        let pages  = max(1, Int(ceil(Double(total) / Double(limit))))
        let offset = (page - 1) * limit
        let paged  = Array(scans.dropFirst(offset).prefix(limit))

        var items: [ScanSummary] = []
        for scan in paged {
            guard let scanID = scan.id else { continue }
            let count = try await Result.query(on: req.db)
                .filter(\Result.$scan.$id == scanID)
                .count()
            items.append(ScanSummary(
                scanID: scanID,
                input: scan.input,
                status: scan.status.rawValue,
                resultCount: count,
                createdAt: scan.createdAt.map { $0.timeIntervalSince1970 },
                completedAt: scan.completedAt.map { $0.timeIntervalSince1970 }
            ))
        }

        return PagedScans(items: items, total: total, page: page, pages: pages)
    }

    @Sendable
    func adminScans(req: Request) async throws -> PagedScans {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }
        guard user.isAdmin else {
            throw Abort(.forbidden, reason: "Admin access required.")
        }

        let page  = max(1, (try? req.query.get(Int.self, at: "page"))  ?? 1)
        let limit = max(1, min(100, (try? req.query.get(Int.self, at: "limit")) ?? 20))
        let q     = try? req.query.get(String.self, at: "q")

        var scans = try await Scan.query(on: req.db)
            .sort(\.$createdAt, .descending)
            .all()

        if let q = q, !q.isEmpty {
            scans = scans.filter { $0.input.localizedCaseInsensitiveContains(q) }
        }

        let total  = scans.count
        let pages  = max(1, Int(ceil(Double(total) / Double(limit))))
        let offset = (page - 1) * limit
        let paged  = Array(scans.dropFirst(offset).prefix(limit))

        var items: [ScanSummary] = []
        for scan in paged {
            guard let scanID = scan.id else { continue }
            let count = try await Result.query(on: req.db)
                .filter(\Result.$scan.$id == scanID)
                .count()
            items.append(ScanSummary(
                scanID: scanID,
                input: maskInput(scan.input),
                status: scan.status.rawValue,
                resultCount: count,
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
