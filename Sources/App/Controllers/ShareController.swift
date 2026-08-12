import Vapor
import Fluent
import Crypto
import SQLKit

struct ShareController: RouteCollection {
    static let maxActiveSharesPerScan = 20
    static let minExpirySeconds = 300
    static let maxExpirySeconds = 30 * 24 * 60 * 60

    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.grouped(ScanRateLimiter(anonMax: 5, authedMax: 10, windowSeconds: 60))
            .post("scans", ":scanID", "share", use: createShare)
        noCache.get("scans", ":scanID", "shares", use: listShares)
        noCache.delete("shares", ":token", use: deleteShare)
        // Public endpoints increment view_count on each hit — rate-limit per IP
        // so a script with a known token cannot inflate viewCount or spam-write
        // the DB. New links carry their bearer token in the URL fragment and
        // submit it in a JSON body, keeping it out of proxy/CDN access logs.
        //
        // GET serves password-free reports and signals 401 when a password is
        // required. POST carries the password in a JSON body: browsers drop the
        // body of a GET (Fetch spec), so a password-protected share is only
        // viewable via POST — the GET-with-body variant never worked client-side.
        noCache.grouped(ScanRateLimiter(anonMax: 30, authedMax: 60, windowSeconds: 60))
            .get("share", ":token", use: viewShare)
        noCache.grouped(ScanRateLimiter(anonMax: 5, authedMax: 10, windowSeconds: 60))
            .post("share", use: viewShareFromBody)
        // Compatibility for already-issued /share/TOKEN links. New clients do
        // not use these token-in-path endpoints.
        noCache.grouped(ScanRateLimiter(anonMax: 5, authedMax: 10, windowSeconds: 60))
            .post("share", ":token", use: viewShare)
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
            let metadata: [String: String]?
        }
        let scan: ScanDTO
        let results: [ResultDTO]
        let sharedAt: Double?
        let viewCount: Int
    }

    @Sendable
    func createShare(req: Request) async throws -> ShareResponse {
        let user = try await mutationUser(req)
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

        if let seconds = body.expiresIn {
            guard (Self.minExpirySeconds...Self.maxExpirySeconds).contains(seconds) else {
                throw Abort(.badRequest, reason: "Expiry must be between 5 minutes and 30 days.")
            }
        }
        let password = body.password?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let password {
            guard (8...72).contains(password.utf8.count) else {
                throw Abort(.badRequest, reason: "Share password must be 8–72 UTF-8 bytes.")
            }
        }

        let token = [UInt8].random(count: 24).base64URLEncoded()
        let tokenHash = sha256Hex(token)
        let expiresAt = body.expiresIn.map { Date().addingTimeInterval(Double($0)) }
        let passwordHash = try password.map { try Bcrypt.hash($0) }

        let share = SharedReport(scanID: scanID, tokenHash: tokenHash, expiresAt: expiresAt, passwordHash: passwordHash)
        try await req.db.transaction { database in
            // Serialize quota checks per scan across all app instances.
            if let sql = database as? SQLDatabase,
               sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw("SELECT id FROM scans WHERE id = \(bind: scanID) FOR UPDATE").run()
            }
            try await SharedReport.query(on: database)
                .filter(\.$scanID == scanID)
                .filter(\.$expiresAt < Date())
                .delete()
            let activeShareCount = try await SharedReport.query(on: database)
                .filter(\.$scanID == scanID)
                .count()
            guard activeShareCount < Self.maxActiveSharesPerScan else {
                throw Abort(.tooManyRequests, reason: "Maximum \(Self.maxActiveSharesPerScan) active links per scan.")
            }
            try await share.save(on: database)
        }
        await AuditLogger.log(req: req, action: "share_created", target: scanID.uuidString)

        let baseURL = (Environment.get("BASE_URL") ?? "https://swift.micutu.com")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return ShareResponse(
            token: token,
            url: "\(baseURL)/share#\(token)",
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
                token: String(s.tokenHash.prefix(8)) + "…",
                expiresAt: s.expiresAt.map { $0.timeIntervalSince1970 },
                viewCount: s.viewCount,
                createdAt: s.createdAt.map { $0.timeIntervalSince1970 }
            )
        }
    }

    @Sendable
    func deleteShare(req: Request) async throws -> HTTPStatus {
        let user = try await mutationUser(req)
        guard let token = req.parameters.get("token"), Self.isValidToken(token) else {
            throw Abort(.notFound)
        }
        let hash = sha256Hex(token)
        guard let share = try await SharedReport.query(on: req.db).filter(\.$tokenHash == hash).first() else {
            throw Abort(.notFound)
        }
        guard let scan = try await Scan.find(share.scanID, on: req.db),
              scan.$user.id == user.id else {
            throw Abort(.forbidden)
        }
        try await share.delete(on: req.db)
        await AuditLogger.log(req: req, action: "share_deleted", target: share.scanID.uuidString)
        return .noContent
    }

    struct PasswordBody: Content { let password: String? }
    struct ShareAccessRequest: Content {
        let token: String
        let password: String?
    }

    @Sendable
    func viewShare(req: Request) async throws -> SharedReportResponse {
        guard let rawToken = req.parameters.get("token"), Self.isValidToken(rawToken) else {
            throw Abort(.notFound)
        }
        let body = (try? req.content.decode(PasswordBody.self)) ?? PasswordBody(password: nil)
        return try await sharedReport(req: req, rawToken: rawToken, password: body.password)
    }

    @Sendable
    func viewShareFromBody(req: Request) async throws -> SharedReportResponse {
        let body = try req.content.decode(ShareAccessRequest.self)
        guard Self.isValidToken(body.token) else {
            throw Abort(.notFound)
        }
        return try await sharedReport(req: req, rawToken: body.token, password: body.password)
    }

    private func sharedReport(req: Request, rawToken: String, password: String?) async throws -> SharedReportResponse {
        let hash = sha256Hex(rawToken)
        guard let share = try await SharedReport.query(on: req.db).filter(\.$tokenHash == hash).first() else {
            throw Abort(.notFound)
        }
        if let exp = share.expiresAt, exp < Date() {
            throw Abort(.gone, reason: "This shared link has expired")
        }
        if let hash = share.passwordHash {
            guard let password, (try? Bcrypt.verify(password, created: hash)) == true else {
                throw Abort(.unauthorized, reason: "Password required")
            }
        }

        guard let scan = try await Scan.find(share.scanID, on: req.db) else {
            throw Abort(.notFound)
        }

        // Increment view count only after confirming the parent still exists.
        share.viewCount += 1
        try await share.save(on: req.db)

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
                    rawData: r.rawData,
                    metadata: r.metadataObject
                )
            },
            sharedAt: share.createdAt.map { $0.timeIntervalSince1970 },
            viewCount: share.viewCount
        )
    }

    private static func isValidToken(_ token: String) -> Bool {
        token.utf8.count == 32
            && token.range(of: "^[A-Za-z0-9_-]{32}$", options: .regularExpression) != nil
    }

    /// Publishing or revoking data needs a recent browser login. Deliberately
    /// scoped API keys remain usable for automation because the scope middleware
    /// has already required `scans:write` for these routes.
    private func mutationUser(_ req: Request) async throws -> User {
        if req.apiKeyAuthorization == nil {
            return try await req.requireRecentSessionUser()
        }
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized)
        }
        return user
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
