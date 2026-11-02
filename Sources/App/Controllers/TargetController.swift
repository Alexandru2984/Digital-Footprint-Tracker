import Vapor
import Fluent
import SQLKit

/// How a domain owner proves control: publish the token in DNS or on the site.
struct DomainProofInstructions: Content {
    let txtName: String
    let txtValue: String
    let fileURL: String
    let fileContent: String
}

struct VerifiedTargetDTO: Content {
    let id: String
    let kind: String
    let value: String
    let verified: Bool
    let method: String?
    let verifiedAt: Double?
    let expiresAt: Double?
    let createdAt: Double?
    /// For an unproven domain: where to publish the token.
    let instructions: DomainProofInstructions?

    init(_ target: VerifiedTarget) throws {
        let value = try target.value
        self.id = target.id?.uuidString ?? ""
        self.kind = target.kind.rawValue
        self.value = value
        self.verified = target.isVerified
        self.method = target.method
        self.verifiedAt = target.verifiedAt?.timeIntervalSince1970
        self.expiresAt = target.isVerified ? nil : target.expiresAt?.timeIntervalSince1970
        self.createdAt = target.createdAt?.timeIntervalSince1970
        if target.kind == .domain, !target.isVerified, let token = target.challenge {
            self.instructions = DomainProofInstructions(
                txtName: "\(TargetOwnership.txtLabel).\(value)",
                txtValue: TargetOwnership.txtPrefix + token,
                fileURL: "https://\(value)\(TargetOwnership.wellKnownPath)",
                fileContent: TargetOwnership.txtPrefix + token
            )
        } else {
            self.instructions = nil
        }
    }
}

struct VerifiedTargetsResponse: Content {
    /// The account's own address, which counts as proven once it is verified.
    let accountEmail: String
    let accountEmailVerified: Bool
    let targets: [VerifiedTargetDTO]
    /// Full scans of targets that are not the account's own, per 24 hours.
    let dailyThirdPartyFullScans: Int
}

/// `/targets`: the addresses and domains an account claims, and proving them.
struct TargetController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let guarded = routes.grouped(NoCacheMiddleware())
            .grouped(ScanRateLimiter(anonMax: 0, authedMax: 120, windowSeconds: 60))
        let targets = guarded.grouped("targets")
        targets.get(use: list)
        let limited = targets.grouped(ScanRateLimiter(anonMax: 0, authedMax: 30, windowSeconds: 3600))
        limited.post(use: start)
        limited.post(":id", "verify", use: verify)
        targets.delete(":id", use: remove)
    }

    private func verifiedUser(_ req: Request) async throws -> User {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard user.emailVerified else {
            throw Abort(.forbidden, reason: "Verify your account email before adding targets.")
        }
        return user
    }

    @Sendable
    func list(req: Request) async throws -> VerifiedTargetsResponse {
        guard let user = try await req.currentUser(), let userID = user.id else { throw Abort(.unauthorized) }
        let rows = try await VerifiedTarget.query(on: req.db)
            .filter(\.$user.$id == userID)
            .sort(\.$createdAt, .ascending)
            .all()
        return VerifiedTargetsResponse(
            accountEmail: user.email,
            accountEmailVerified: user.emailVerified,
            targets: rows.compactMap { try? VerifiedTargetDTO($0) },
            dailyThirdPartyFullScans: TargetOwnership.dailyThirdPartyFullScans
        )
    }

    /// POST /targets {value} — claims an address or domain. An address gets a
    /// code by email; a domain gets a token to publish. Claiming the same value
    /// again resends the code (within limits) or returns the same token.
    @Sendable
    func start(req: Request) async throws -> VerifiedTargetDTO {
        let user = try await verifiedUser(req)
        guard let userID = user.id else { throw Abort(.unauthorized) }
        struct Body: Content { var value: String }
        let body = try req.content.decode(Body.self)
        guard body.value.utf8.count <= 255, let claim = TargetOwnership.claim(body.value) else {
            throw Abort(.badRequest, reason: "Enter an email address or a domain name.")
        }
        if claim.kind == .email, EmailAddress.normalize(user.email) == claim.value {
            throw Abort(.badRequest, reason: "Your account address already counts as yours.")
        }
        guard !SSRFGuard.isInternalTarget(claim.value) else {
            throw Abort(.badRequest, reason: "Internal or private names cannot be claimed.")
        }

        let target: VerifiedTarget = try await req.db.transaction { database in
            if let sql = database as? SQLDatabase, sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw("SELECT id FROM users WHERE id = \(bind: userID) FOR UPDATE").run()
            }
            let hashes = FieldCrypto.blindIndexCandidates(claim.value)
            let existing = try await VerifiedTarget.query(on: database)
                .filter(\.$user.$id == userID)
                .filter(\.$valueHash ~~ hashes)
                .all()
                .first { (try? $0.value) == claim.value && $0.kind == claim.kind }
            if let existing { return existing }
            let rows = try await VerifiedTarget.query(on: database).filter(\.$user.$id == userID).all()
            guard rows.count < TargetOwnership.maxClaims else {
                throw Abort(.tooManyRequests, reason: "Maximum \(TargetOwnership.maxClaims) targets per account.")
            }
            let now = Date()
            let pending = rows.filter { !$0.isVerified && ($0.expiresAt ?? .distantPast) > now }
            guard pending.count < TargetOwnership.maxPending else {
                throw Abort(.tooManyRequests,
                            reason: "Finish or remove a pending target first (at most \(TargetOwnership.maxPending) at a time).")
            }
            let created = VerifiedTarget(userID: userID, kind: claim.kind, value: claim.value)
            try await created.save(on: database)
            return created
        }

        guard !target.isVerified else { return try VerifiedTargetDTO(target) }
        guard let targetID = target.id else { throw Abort(.internalServerError) }
        let now = Date()
        switch claim.kind {
        case .domain:
            if target.challenge == nil || (target.expiresAt ?? .distantPast) <= now {
                target.challenge = TargetOwnership.newToken()
                target.expiresAt = now.addingTimeInterval(TargetOwnership.tokenLifetime)
                target.attempts = 0
                try await target.save(on: req.db)
            }
        case .email:
            if let last = target.lastSentAt, now.timeIntervalSince(last) < TargetOwnership.resendInterval {
                throw Abort(.tooManyRequests, reason: "A code was just sent. Wait a minute before asking for another.")
            }
            guard target.sends < TargetOwnership.maxSends else {
                throw Abort(.tooManyRequests, reason: "Too many codes were sent to this address. Remove it and try again later.")
            }
            let code = TargetOwnership.newCode()
            target.challenge = TargetOwnership.codeDigest(code, claimID: targetID)
            target.expiresAt = now.addingTimeInterval(TargetOwnership.codeLifetime)
            target.attempts = 0
            target.sends += 1
            target.lastSentAt = now
            try await target.save(on: req.db)
            let outcome = await EmailService.send(
                to: claim.value,
                subject: "Your verification code",
                body: Self.codeEmail(code: code),
                app: req.application
            )
            if outcome == .failed {
                throw Abort(.badGateway, reason: "The code could not be sent. Try again in a few minutes.")
            }
        }
        await AuditLogger.log(req: req, action: "target_verify_start", target: "\(claim.kind.rawValue):\(claim.value)")
        return try VerifiedTargetDTO(target)
    }

    static func codeEmail(code: String) -> String {
        """
        Someone using the Digital Footprint Tracker (swift.micutu.com) asked to \
        confirm that they control this email address, so that it can be checked \
        more thoroughly.

        Your code: \(code)

        It expires in 15 minutes. If you did not ask for this, ignore this email: \
        nothing is unlocked without the code.
        """
    }

    /// POST /targets/:id/verify {code?} — checks a mailed code, or looks for a
    /// domain's token in DNS and on the site.
    @Sendable
    func verify(req: Request) async throws -> VerifiedTargetDTO {
        let user = try await verifiedUser(req)
        let target = try await owned(req, user: user)
        guard !target.isVerified else { return try VerifiedTargetDTO(target) }
        guard let targetID = target.id, let challenge = target.challenge,
              let expires = target.expiresAt, expires > Date() else {
            throw Abort(.gone, reason: target.kind == .email
                        ? "The code has expired. Ask for a new one."
                        : "The token has expired. Add the domain again for a new one.")
        }
        let value = try target.value
        switch target.kind {
        case .email:
            struct Body: Content { var code: String }
            let code = (try? req.content.decode(Body.self).code)?
                .filter { !$0.isWhitespace } ?? ""
            guard target.attempts < TargetOwnership.maxAttempts else {
                throw Abort(.tooManyRequests, reason: "Too many wrong codes. Ask for a new one.")
            }
            guard code.count == 6, code.allSatisfy(\.isASCII), code.allSatisfy(\.isNumber),
                  TargetOwnership.codeDigest(code, claimID: targetID) == challenge else {
                target.attempts += 1
                if target.attempts >= TargetOwnership.maxAttempts { target.challenge = nil }
                try await target.save(on: req.db)
                let left = max(0, TargetOwnership.maxAttempts - target.attempts)
                throw Abort(.badRequest, reason: left > 0
                            ? "Wrong code. \(left) attempt(s) left."
                            : "Too many wrong codes. Ask for a new one.")
            }
            target.method = "email_code"
        case .domain:
            guard let method = await TargetOwnership.domainProbe(for: req.application)(value, challenge, req.application) else {
                throw Abort(.conflict, reason: "The token was not found yet. DNS changes can take a few minutes to appear.")
            }
            target.method = method
        }
        target.verifiedAt = Date()
        target.challenge = nil
        target.expiresAt = nil
        target.attempts = 0
        try await target.save(on: req.db)
        await AuditLogger.log(req: req, action: "target_verified", target: "\(target.kind.rawValue):\(value)")
        return try VerifiedTargetDTO(target)
    }

    @Sendable
    func remove(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let target = try await owned(req, user: user)
        let label = "\(target.kind.rawValue):\((try? target.value) ?? "?")"
        try await target.delete(on: req.db)
        await AuditLogger.log(req: req, action: "target_removed", target: label)
        return .noContent
    }

    private func owned(_ req: Request, user: User) async throws -> VerifiedTarget {
        guard let raw = req.parameters.get("id"), let id = UUID(uuidString: raw) else { throw Abort(.badRequest) }
        guard let target = try await VerifiedTarget.find(id, on: req.db), target.$user.id == user.id else {
            throw Abort(.notFound)
        }
        return target
    }
}
