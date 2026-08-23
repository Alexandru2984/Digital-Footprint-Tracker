import Vapor
import Fluent
import SQLKit

/// Two-factor authentication (TOTP) endpoints.
///
/// Enrolment (all require an authenticated session):
///   POST /auth/2fa/setup   → issue a secret + otpauth URI (not yet active)
///   POST /auth/2fa/enable  → prove possession with a code, receive recovery codes
///   POST /auth/2fa/disable → turn 2FA off (prove password + current second factor)
///
/// Login second step (no session yet — gated by a short-lived pending marker
/// that `AuthController.login` sets after the password checks out):
///   POST /auth/2fa/verify  → submit a TOTP or recovery code to finish logging in
struct TwoFactorController: RouteCollection {
    /// Pending-login marker must be redeemed within this window.
    private static let pendingTTL: TimeInterval = 300

    func boot(routes: RoutesBuilder) throws {
        let twofa = routes.grouped("auth", "2fa")
        let sensitive = twofa.grouped(AuthRateLimiter(maxAttempts: 5, windowSeconds: 600))
        sensitive.post("setup", use: setup)
        sensitive.post("enable", use: enable)
        sensitive.post("disable", use: disable)
        // The verify step is pre-session; rate-limit it like login to slow code
        // guessing (10^6 space, ±1 step ⇒ brute-forceable without a cap).
        twofa.grouped(AuthRateLimiter(maxAttempts: 10, windowSeconds: 300))
             .post("verify", use: verify)
    }

    // MARK: - Enrolment

    struct SetupResponse: Content { let secret: String; let otpauthURI: String }

    @Sendable
    func setup(req: Request) async throws -> SetupResponse {
        let user = try await req.requireRecentSessionUser()
        guard !user.totpEnabled else {
            throw Abort(.conflict, reason: "Two-factor authentication is already enabled.")
        }
        let secret = TOTP.generateSecret()
        user.setTOTPSecret(Self.storeSecret(secret))
        try await user.save(on: req.db)

        let issuer = URL(string: Environment.get("ALLOWED_ORIGIN") ?? "https://swift.micutu.com")?.host ?? "swift.micutu.com"
        let uri = TOTP.provisioningURI(secret: secret, account: user.username, issuer: issuer)
        return SetupResponse(secret: secret, otpauthURI: uri)
    }

    struct CodeBody: Content { let code: String }
    struct EnableResponse: Content { let recoveryCodes: [String] }

    @Sendable
    func enable(req: Request) async throws -> EnableResponse {
        let user = try await req.requireRecentSessionUser()
        guard !user.totpEnabled else { throw Abort(.conflict, reason: "Already enabled.") }
        guard let stored = try user.totpSecret, let secret = Self.readSecret(stored) else {
            throw Abort(.badRequest, reason: "Run setup first.")
        }
        let body = try req.content.decode(CodeBody.self)
        guard let step = TOTP.matchedStep(code: body.code, secret: secret),
              let userID = user.id,
              try await Self.consumeTotpStep(step, userID: userID, db: req.db) else {
            throw Abort(.badRequest, reason: "Incorrect code — check your authenticator's clock and try again.")
        }
        let codes = RecoveryCodes.generate()
        let hashes = codes.map { RecoveryCodes.hash($0) }
        if let data = try? JSONEncoder().encode(hashes) {
            user.totpRecoveryCodes = String(data: data, encoding: .utf8)
        }
        user.totpEnabled = true
        // Keep the in-memory model in sync with the row updated by
        // consumeTotpStep so this save cannot overwrite replay protection.
        user.lastTotpStep = step
        try await user.save(on: req.db)
        await AuditLogger.log(req: req, action: "2fa_enabled", target: user.username)
        return EnableResponse(recoveryCodes: codes)
    }

    struct DisableBody: Content {
        let password: String
        let code: String
    }

    @Sendable
    func disable(req: Request) async throws -> User.Public {
        let user = try await req.requireSessionUser()
        guard user.totpEnabled else {
            throw Abort(.conflict, reason: "Two-factor authentication is not enabled.")
        }
        let body = try req.content.decode(DisableBody.self)
        guard try await req.password.async.verify(body.password, created: user.passwordHash) else {
            throw Abort(.unauthorized, reason: "Invalid credentials.")
        }
        guard try await Self.verifySecondFactor(body.code, user: user, db: req.db) else {
            throw Abort(.unauthorized, reason: "Invalid credentials.")
        }
        user.totpEnabled = false
        user.setTOTPSecret(nil)
        user.totpRecoveryCodes = nil
        user.lastTotpStep = nil
        try await user.save(on: req.db)
        guard let userID = user.id else { throw Abort(.internalServerError) }
        // Rotate after the security downgrade so copies of the old session ID
        // do not remain valid after this high-impact operation.
        try await SessionSecurity.establishAuthenticated(userID: userID, on: req)
        await AuditLogger.log(req: req, action: "2fa_disabled", target: user.username)
        return try user.toPublic()
    }

    // MARK: - Login second step

    @Sendable
    func verify(req: Request) async throws -> User.Public {
        guard let idString = req.session.data["pending2FAUserID"], let userID = UUID(idString) else {
            throw Abort(.unauthorized, reason: "No pending login. Start at /login.")
        }
        // Reject missing, malformed, future-dated, and stale pending markers.
        let now = Date().timeIntervalSince1970
        guard let atStr = req.session.data["pending2FAAt"], let at = Double(atStr),
              now >= at, now - at <= Self.pendingTTL else {
            req.session.destroy()
            throw Abort(.unauthorized, reason: "Login timed out. Please sign in again.")
        }
        guard let user = try await User.find(userID, on: req.db), user.totpEnabled else {
            req.session.destroy()
            throw Abort(.unauthorized)
        }
        let body = try req.content.decode(CodeBody.self)
        let submitted = body.code.trimmingCharacters(in: .whitespaces)

        let ok = try await Self.verifySecondFactor(submitted, user: user, db: req.db)
        guard ok else {
            throw Abort(.unauthorized, reason: "Invalid code.")
        }

        guard let userID = user.id else { throw Abort(.internalServerError) }
        try await SessionSecurity.establishAuthenticated(userID: userID, on: req)
        await AuditLogger.log(req: req, action: "login_2fa", target: user.username)
        return try user.toPublic()
    }

    static func verifySecondFactor(_ submitted: String, user: User, db: Database) async throws -> Bool {
        guard let stored = try user.totpSecret, let secret = readSecret(stored) else { return false }
        let normalized = submitted.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty, normalized.utf8.count <= 64 else { return false }
        if let step = TOTP.matchedStep(code: normalized, secret: secret) {
            guard let userID = user.id else { return false }
            return try await consumeTotpStep(step, userID: userID, db: db)
        }
        guard let userID = user.id else { return false }
        return try await consumeRecoveryCode(normalized, userID: userID, db: db)
    }

    /// Atomically accept a TOTP time-step exactly once. Rejects a step at or
    /// below the last accepted one (replay), and records the new step under the
    /// same row lock the recovery-code path uses so two concurrent submissions of
    /// the same code cannot both pass.
    private static func consumeTotpStep(_ step: Int, userID: UUID, db: Database) async throws -> Bool {
        try await db.transaction { transaction in
            if let sql = transaction as? SQLDatabase,
               sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw("SELECT id FROM users WHERE id = \(bind: userID) FOR UPDATE").run()
            }
            guard let lockedUser = try await User.find(userID, on: transaction) else { return false }
            if let last = lockedUser.lastTotpStep, step <= last { return false } // replay
            lockedUser.lastTotpStep = step
            try await lockedUser.save(on: transaction)
            return true
        }
    }

    /// If `submitted` matches an unused recovery-code hash, consume it and return true.
    private static func consumeRecoveryCode(_ submitted: String, userID: UUID, db: Database) async throws -> Bool {
        try await db.transaction { transaction in
            // PostgreSQL row locking makes read-remove-save atomic across app
            // processes. SQLite's transaction is serialized in the test path.
            if let sql = transaction as? SQLDatabase,
               sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw("SELECT id FROM users WHERE id = \(bind: userID) FOR UPDATE").run()
            }
            guard let lockedUser = try await User.find(userID, on: transaction),
                  let raw = lockedUser.totpRecoveryCodes,
                  let data = raw.data(using: .utf8),
                  var hashes = try? JSONDecoder().decode([String].self, from: data) else { return false }
            let candidate = RecoveryCodes.hash(submitted)
            guard let idx = hashes.firstIndex(of: candidate) else { return false }
            hashes.remove(at: idx)
            let encoded = try JSONEncoder().encode(hashes)
            lockedUser.totpRecoveryCodes = String(decoding: encoded, as: UTF8.self)
            try await lockedUser.save(on: transaction)
            return true
        }
    }

    // MARK: - Secret at-rest helpers

    /// The model also encrypts this field; these helpers keep the enrolment code
    /// explicit and retain compatibility with legacy plaintext rows.
    static func storeSecret(_ secret: String) -> String {
        return secret
    }

    static func readSecret(_ stored: String) -> String? {
        return stored
    }
}
