import Vapor
import Fluent

struct ScanSummary: Content {
    let scanID: UUID?
    let inputMasked: String
    let status: String
    let createdAt: Double?
    let completedAt: Double?
}

struct UserController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.get("my-scans", use: myScans)
        noCache.get("admin", "scans", use: adminScans)
    }

    @Sendable
    func myScans(req: Request) async throws -> [ScanSummary] {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }

        let scans = try await Scan.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .sort(\.$createdAt, .descending)
            .limit(50)
            .all()

        return scans.map { makeSummary($0) }
    }

    @Sendable
    func adminScans(req: Request) async throws -> [ScanSummary] {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }
        guard user.isAdmin else {
            throw Abort(.forbidden, reason: "Admin access required.")
        }

        let scans = try await Scan.query(on: req.db)
            .sort(\.$createdAt, .descending)
            .limit(100)
            .all()

        return scans.map { makeSummary($0) }
    }

    private func makeSummary(_ scan: Scan) -> ScanSummary {
        // Mask PII: show domain for emails, first 3 chars + *** for others
        let masked: String
        if let atIdx = scan.input.firstIndex(of: "@") {
            masked = "*@" + String(scan.input[scan.input.index(after: atIdx)...])
        } else if scan.input.count > 3 {
            masked = String(scan.input.prefix(3)) + "***"
        } else {
            masked = "***"
        }

        return ScanSummary(
            scanID: scan.id,
            inputMasked: masked,
            status: scan.status.rawValue,
            createdAt: scan.createdAt.map { $0.timeIntervalSince1970 },
            completedAt: scan.completedAt.map { $0.timeIntervalSince1970 }
        )
    }
}
