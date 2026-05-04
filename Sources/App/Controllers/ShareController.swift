import Vapor
import Fluent
import Crypto

struct ShareController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.post("scans", ":scanID", "share", use: createShare)
        noCache.get("scans", ":scanID", "shares", use: listShares)
        noCache.delete("shares", ":token", use: deleteShare)
        noCache.get("share", ":token", use: viewShare)
    }

    struct CreateShareRequest: Content {
        let expiresIn: Int?   // seconds from now
        let password: String?
    }

    struct ShareResponse: Content {
        let token: String
        let url: String
        let expiresAt: Double?
        let createdAt: Double?
    }

    struct ShareDetail: Content {
        let token: String
        let expiresAt: Double?
        let viewCount: Int
        let createdAt: Double?
    }

    struct SharedReportResponse: Content {
        struct ScanDTO: Content {
            let id: String
            let input: String
            let status: String
            let completedAt: Double?
            let scannedAt: Double?
        }
        struct ResultDTO: Content {
            let id: String?
            let source: String
            let type: String
            let confidenceScore: Double
            let rawData: String
        }
        let scan: ScanDTO
        let results: [ResultDTO]
        let sharedAt: Double?
        let viewCount: Int
    }

    @Sendable
    func createShare(req: Request) async throws -> ShareResponse {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized)
        }
        guard let scanIDStr = req.parameters.get("scanID"),
              let scanID = UUID(uuidString: scanIDStr) else {
            throw Abort(.badRequest, reason: "Invalid scanID")
        }
        guard let scan = try await Scan.find(scanID, on: req.db) else {
            throw Abort(.notFound)
        }
        guard scan.$user.id == user.id else {
            throw Abort(.forbidden)
        }

        let body = try req.content.decode(CreateShareRequest.self)

        let token = [UInt8].random(count: 24).base64URLEncoded()
        let expiresAt = body.expiresIn.map { Date().addingTimeInterval(Double($0)) }
        let passwordHash = try body.password.map { try Bcrypt.hash($0) }

        let share = SharedReport(scanID: scanID, token: token, expiresAt: expiresAt, passwordHash: passwordHash)
        try await share.save(on: req.db)

        let baseURL = Environment.get("BASE_URL") ?? "https://swift.micutu.com"
        return ShareResponse(
            token: token,
            url: "\(baseURL)/share/\(token)",
            expiresAt: expiresAt.map { $0.timeIntervalSince1970 },
            createdAt: share.createdAt.map { $0.timeIntervalSince1970 }
        )
    }

    @Sendable
    func listShares(req: Request) async throws -> [ShareDetail] {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized)
        }
        guard let scanIDStr = req.parameters.get("scanID"),
              let scanID = UUID(uuidString: scanIDStr) else {
            throw Abort(.badRequest, reason: "Invalid scanID")
        }
        guard let scan = try await Scan.find(scanID, on: req.db) else {
            throw Abort(.notFound)
        }
        guard scan.$user.id == user.id else {
            throw Abort(.forbidden)
        }

        let shares = try await SharedReport.query(on: req.db)
            .filter(\.$scanID == scanID)
            .sort(\.$createdAt, .descending)
            .all()

        return shares.map { s in
            ShareDetail(
                token: s.token,
                expiresAt: s.expiresAt.map { $0.timeIntervalSince1970 },
                viewCount: s.viewCount,
                createdAt: s.createdAt.map { $0.timeIntervalSince1970 }
            )
        }
    }

    @Sendable
    func deleteShare(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized)
        }
        guard let token = req.parameters.get("token") else {
            throw Abort(.badRequest)
        }
        guard let share = try await SharedReport.query(on: req.db).filter(\.$token == token).first() else {
            throw Abort(.notFound)
        }
        guard let scan = try await Scan.find(share.scanID, on: req.db),
              scan.$user.id == user.id else {
            throw Abort(.forbidden)
        }
        try await share.delete(on: req.db)
        return .noContent
    }

    struct PasswordBody: Content { let password: String? }

    @Sendable
    func viewShare(req: Request) async throws -> SharedReportResponse {
        guard let token = req.parameters.get("token") else {
            throw Abort(.badRequest)
        }
        guard let share = try await SharedReport.query(on: req.db).filter(\.$token == token).first() else {
            throw Abort(.notFound)
        }
        if let exp = share.expiresAt, exp < Date() {
            throw Abort(.gone, reason: "This shared link has expired")
        }
        if let hash = share.passwordHash {
            let body = (try? req.content.decode(PasswordBody.self)) ?? PasswordBody(password: nil)
            guard let provided = body.password, (try? Bcrypt.verify(provided, created: hash)) == true else {
                throw Abort(.unauthorized, reason: "Password required")
            }
        }

        // Increment view count
        share.viewCount += 1
        try await share.save(on: req.db)

        guard let scan = try await Scan.find(share.scanID, on: req.db) else {
            throw Abort(.notFound)
        }
        let results = try await App.Result.query(on: req.db).filter(\.$scan.$id == scan.id!).all()

        return SharedReportResponse(
            scan: SharedReportResponse.ScanDTO(
                id: scan.id!.uuidString,
                input: scan.input,
                status: scan.status.rawValue,
                completedAt: scan.completedAt.map { $0.timeIntervalSince1970 },
                scannedAt: scan.createdAt.map { $0.timeIntervalSince1970 }
            ),
            results: results.map { r in
                SharedReportResponse.ResultDTO(
                    id: r.id?.uuidString,
                    source: r.source,
                    type: r.type,
                    confidenceScore: r.confidenceScore,
                    rawData: r.rawData
                )
            },
            sharedAt: share.createdAt.map { $0.timeIntervalSince1970 },
            viewCount: share.viewCount
        )
    }
}

// MARK: - Helpers

private extension Array where Element == UInt8 {
    static func random(count: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return (0..<count).map { _ in rng.next() }
    }
    func base64URLEncoded() -> String {
        Data(self).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
