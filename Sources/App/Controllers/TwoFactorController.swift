import Vapor
import Fluent

/// Two-factor authentication (TOTP) endpoints.
///
/// Enrolment (all require an authenticated session):
///   POST /auth/2fa/setup   → issue a secret + otpauth URI (not yet active)
///   POST /auth/2fa/enable  → prove possession with a code, receive recovery codes
///   POST /auth/2fa/disable → turn 2FA off (re-auth with the account password)
///
/// Login second step (no session yet — gated by a short-lived pending marker
/// that `AuthController.login` sets after the password checks out):
///   POST /auth/2fa/verify  → submit a TOTP or recovery code to finish logging in
struct TwoFactorController: RouteCollection {
    /// Pending-login marker must be redeemed within this window.
    private static let pendingTTL: TimeInterval = 300

    func boot(routes: RoutesBuilder) throws {
        let twofa = routes.grouped("auth", "2fa")
        twofa.post("setup", use: setup)
        twofa.post("enable", use: enable)
        twofa.post("disable", use: disable)
        // The verify step is pre-session; rate-limit it like login to slow code
        // guessing (10^6 space, ±1 step ⇒ brute-forceable without a cap).
        twofa.grouped(AuthRateLimiter(maxAttempts: 10, windowSeconds: 300))
             .post("verify", use: verify)
    }

    // MARK: - Enrolment

    struct SetupResponse: Content { let secret: String; let otpauthURI: String }

    @Sendable
    func setup(req: Request) async throws -> SetupResponse {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard !user.totpEnabled else {
            throw Abort(.conflict, reason: "Two-factor authentication is already enabled.")
        }
        let secret = TOTP.generateSecret()
        user.totpSecret = Self.storeSecret(secret)
        try await user.save(on: req.db)

        let issuer = URL(string: Environment.get("ALLOWED_ORIGIN") ?? "https://swift.micutu.com")?.host ?? "swift.micutu.com"
        let uri = TOTP.provisioningURI(secret: secret, account: user.username, issuer: issuer)
        return SetupResponse(secret: secret, otpauthURI: uri)
    }

    struct CodeBody: Content { let code: String }
    struct EnableResponse: Content { let recoveryCodes: [String] }

    @Sendable
    func enable(req: Request) async throws -> EnableResponse {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard !user.totpEnabled else { throw Abort(.conflict, reason: "Already enabled.") }
        guard let stored = user.totpSecret, let secret = Self.readSecret(stored) else {
            throw Abort(.badRequest, reason: "Run setup first.")
        }
        let body = try req.content.decode(CodeBody.self)
        guard TOTP.verify(code: body.code, secret: secret) else {
            throw Abort(.badRequest, reason: "Incorrect code — check your authenticator's clock and try again.")
        }
        let codes = RecoveryCodes.generate()
        let hashes = codes.map { RecoveryCodes.hash($0) }
        if let data = try? JSONEncoder().encode(hashes) {
            user.totpRecoveryCodes = String(data: data, encoding: .utf8)
        }
        user.totpEnabled = true
        try await user.save(on: req.db)
        AuditLogger.log(req: req, action: "2fa_enabled", target: user.username)
        return EnableResponse(recoveryCodes: codes)
    }

    struct DisableBody: Content { let password: String }

    @Sendable
    func disable(req: Request) async throws -> User.Public {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let body = try req.content.decode(DisableBody.self)
        guard try await req.password.async.verify(body.password, created: user.passwordHash) else {
            throw Abort(.unauthorized, reason: "Incorrect password.")
        }
        user.totpEnabled = false
        user.totpSecret = nil
        user.totpRecoveryCodes = nil
        try await user.save(on: req.db)
        AuditLogger.log(req: req, action: "2fa_disabled", target: user.username)
        return user.toPublic()
    }

    // MARK: - Login second step

    @Sendable
    func verify(req: Request) async throws -> User.Public {
        guard let idString = req.session.data["pending2FAUserID"], let userID = UUID(idString) else {
            throw Abort(.unauthorized, reason: "No pending login. Start at /login.")
        }
        // Reject a stale pending marker.
        if let atStr = req.session.data["pending2FAAt"], let at = Double(atStr),
           Date().timeIntervalSince1970 - at > Self.pendingTTL {
            req.session.destroy()
            throw Abort(.unauthorized, reason: "Login timed out. Please sign in again.")
        }
        guard let user = try await User.find(userID, on: req.db), user.totpEnabled,
              let stored = user.totpSecret, let secret = Self.readSecret(stored) else {
            req.session.destroy()
            throw Abort(.unauthorized)
        }
        let body = try req.content.decode(CodeBody.self)
        let submitted = body.code.trimmingCharacters(in: .whitespaces)

        var ok = TOTP.verify(code: submitted, secret: secret)
        if !ok { ok = try await consumeRecoveryCode(submitted, user: user, db: req.db) }
        guard ok else {
            throw Abort(.unauthorized, reason: "Invalid code.")
        }

        // Success — clear the pending marker and authenticate. Use `data = .init()`
        // (as login/register do) rather than `destroy()`: destroying the session
        // here invalidates the cookie so the freshly-set userID never sticks.
        req.session.data = .init()
        req.session.data["userID"] = user.id?.uuidString
        AuditLogger.log(req: req, action: "login_2fa", target: user.username)
        return user.toPublic()
    }

    /// If `submitted` matches an unused recovery-code hash, consume it and return true.
    private func consumeRecoveryCode(_ submitted: String, user: User, db: Database) async throws -> Bool {
        guard let raw = user.totpRecoveryCodes,
              let data = raw.data(using: .utf8),
              var hashes = try? JSONDecoder().decode([String].self, from: data) else { return false }
        let candidate = RecoveryCodes.hash(submitted)
        guard let idx = hashes.firstIndex(of: candidate) else { return false }
        hashes.remove(at: idx)
        if let data = try? JSONEncoder().encode(hashes) {
            user.totpRecoveryCodes = String(data: data, encoding: .utf8)
        }
        try await user.save(on: db)
        return true
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
