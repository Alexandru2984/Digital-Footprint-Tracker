import Vapor
import Fluent

struct RegisterRequest: Content {
    let username: String
    let email: String
    let password: String
}

struct LoginRequest: Content {
    let username: String
    let password: String
}

/// Login result: either the authenticated user, or a signal that a second
/// factor is required. When `twoFactorRequired` is true the session holds a
/// short-lived pending marker and the client must call `/auth/2fa/verify`.
struct LoginResponse: Content {
    let twoFactorRequired: Bool
    let user: User.Public?
}

struct AuthController: RouteCollection {

    /// Precomputed BCrypt hash used to keep login response time independent of
    /// whether the queried username exists.
    ///
    /// Without this, a missing user short-circuits before BCrypt and the
    /// response returns in ~1 ms, while a real user with a wrong password
    /// takes ~100 ms (cost 12). The measurable difference lets an attacker
    /// enumerate valid usernames by timing alone.
    ///
    /// Cost MUST match `req.password` (default 12) so verify times align.
    /// `static let` is thread-safe and computed lazily on first access; first
    /// login after process start absorbs the ~100 ms hash cost once.
    private static let dummyPasswordHash: String = {
        (try? Bcrypt.hash("never-a-real-password-\(UUID().uuidString)", cost: 12)) ?? ""
    }()

    func boot(routes: RoutesBuilder) throws {
        let auth = routes.grouped("auth")
        let limited = auth.grouped(AuthRateLimiter(maxAttempts: 10, windowSeconds: 300))
        limited.post("register", use: register)
        limited.post("login", use: login)
        limited.post("reauth", use: reauthenticate)
        auth.post("logout", use: logout)
        auth.get("me", use: me)
        auth.get("verify-email", use: verifyEmail)
        limited.post("resend-verification", use: resendVerification)
        auth.post("webhook", use: setWebhook)
        auth.post("retention", use: setRetention)
        auth.patch("settings", use: updateSettings)
        auth.post("notifications", "test", use: testNotifications)
    }

    @Sendable
    func register(req: Request) async throws -> User.Public {
        let body = try req.content.decode(RegisterRequest.self)

        // Validate
        guard body.username.count >= 3, body.username.count <= 30 else {
            throw Abort(.badRequest, reason: "Username must be 3–30 characters.")
        }
        guard body.username.range(of: "^[a-zA-Z0-9_-]+$", options: .regularExpression) != nil else {
            throw Abort(.badRequest, reason: "Username may only contain letters, numbers, hyphens and underscores.")
        }
        guard body.email.contains("@"), body.email.count <= 254 else {
            throw Abort(.badRequest, reason: "Invalid email address.")
        }
        guard body.password.count >= 8 else {
            throw Abort(.badRequest, reason: "Password must be at least 8 characters.")
        }
        // Offline weak-password rejection — no third-party HIBP call, honours the
        // privacy-first stance. Blocks the passwords attackers try first.
        try PasswordStrength.validate(body.password, username: body.username, email: body.email)

        // Uniqueness check. Both queries run concurrently and the response
        // returns a single generic reason regardless of which constraint
        // failed — distinct messages would let an attacker enumerate
        // registered usernames AND email addresses by trial registration.
        // (A stronger mitigation — accept registration silently and send an
        // email verification link — is out of scope here; this is the
        // single-message hardening.)
        async let usernameTask = User.query(on: req.db).filter(\.$username == body.username).first()
        async let emailTask    = User.query(on: req.db).filter(\.$email == body.email.lowercased()).first()
        let (existingUsername, existingEmail) = try await (usernameTask, emailTask)
        if existingUsername != nil || existingEmail != nil {
            // Log internally for ops, generic response externally.
            req.logger.debug("Registration rejected (username conflict: \(existingUsername != nil), email conflict: \(existingEmail != nil))")
            throw Abort(.conflict, reason: "Registration failed: that username or email is already in use.")
        }

        let hash = try await req.password.async.hash(body.password)
        let user = User(username: body.username, email: body.email.lowercased(), passwordHash: hash)
        try await user.save(on: req.db)

        AuditLogger.log(req: req, action: "register", target: body.username)

        // Issue an email-verification token (raw in the email, hash at rest) and
        // send the link. Best-effort: a mail failure must not fail registration.
        await sendVerificationEmail(for: user, req: req)

        guard let userID = user.id else { throw Abort(.internalServerError) }
        try await SessionSecurity.establishAuthenticated(userID: userID, on: req)

        return user.toPublic()
    }

    // MARK: - Email verification

    /// Generate + persist a fresh verification token and email the link.
    private func sendVerificationEmail(for user: User, req: Request) async {
        // 32 random bytes as hex (URL-safe, no encoding pitfalls). Only the hash
        // is stored; the raw token lives only in the email link.
        let rawToken = (0..<32).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
        user.emailVerificationToken = sha256Hex(rawToken)
        user.emailVerificationExpires = Date().addingTimeInterval(24 * 3600)
        try? await user.save(on: req.db)

        let base = Environment.get("ALLOWED_ORIGIN") ?? "https://swift.micutu.com"
        let link = "\(base)/api/auth/verify-email?token=\(rawToken)"
        let body = """
        Hi \(user.username),

        Confirm your email address for the OSINT Footprint Tracker by opening:

        \(link)

        This link expires in 24 hours. If you didn't create an account, ignore this email.
        """
        await EmailService.send(to: user.email, subject: "Verify your email", body: body, app: req.application)
    }

    /// GET /auth/verify-email?token=… — clicked from the email, so it returns a
    /// small HTML page rather than JSON.
    @Sendable
    func verifyEmail(req: Request) async throws -> Response {
        let token = try req.query.get(String.self, at: "token")
        let hash = sha256Hex(token)
        let user = try await User.query(on: req.db)
            .filter(\.$emailVerificationToken == hash)
            .first()
        let ok: Bool
        if let user, let exp = user.emailVerificationExpires, exp > Date() {
            user.emailVerified = true
            user.emailVerificationToken = nil
            user.emailVerificationExpires = nil
            try await user.save(on: req.db)
            AuditLogger.log(req: req, action: "email_verified", target: user.username)
            ok = true
        } else {
            ok = false
        }
        let title = ok ? "Email verified ✓" : "Verification failed"
        let msg = ok
            ? "Your email address is confirmed. You can close this tab and return to the app."
            : "This verification link is invalid or has expired. Sign in and request a new one."
        let html = """
        <!doctype html><html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>\(title)</title></head>
        <body style="font-family:system-ui,sans-serif;background:#0f172a;color:#f8fafc;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">
        <div style="max-width:28rem;padding:2rem;text-align:center">
        <h1 style="color:\(ok ? "#10b981" : "#f87171")">\(title)</h1>
        <p style="color:#cbd5e1">\(msg)</p>
        <a href="/" style="color:#10b981">← Back to the app</a>
        </div></body></html>
        """
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "text/html; charset=utf-8")
        return Response(status: ok ? .ok : .badRequest, headers: headers, body: .init(string: html))
    }

    /// POST /auth/resend-verification — authenticated; re-sends the link.
    @Sendable
    func resendVerification(req: Request) async throws -> HTTPStatus {
        let user = try await req.requireSessionUser()
        guard !user.emailVerified else { throw Abort(.badRequest, reason: "Email is already verified.") }
        await sendVerificationEmail(for: user, req: req)
        return .accepted
    }

    @Sendable
    func login(req: Request) async throws -> LoginResponse {
        let body = try req.content.decode(LoginRequest.self)

        let existingUser = try await User.query(on: req.db)
            .filter(\.$username == body.username)
            .first()

        // Always run BCrypt verify — fall back to a dummy hash if no user
        // matched the username. Equalises response time so an attacker
        // cannot enumerate valid usernames by measuring how long
        // /auth/login takes (see `dummyPasswordHash` comment).
        let hashToVerify = existingUser?.passwordHash ?? AuthController.dummyPasswordHash
        let passwordValid = try await req.password.async.verify(body.password, created: hashToVerify)

        guard let user = existingUser, passwordValid else {
            throw Abort(.unauthorized, reason: "Invalid username or password.")
        }

        // If the account has 2FA, do NOT authenticate yet. Stash a short-lived
        // pending marker (cleared on success/timeout in TwoFactorController) and
        // ask the client for the second factor.
        if user.totpEnabled {
            guard let userID = user.id else { throw Abort(.internalServerError) }
            try await SessionSecurity.establishPendingTwoFactor(userID: userID, on: req)
            return LoginResponse(twoFactorRequired: true, user: nil)
        }

        guard let userID = user.id else { throw Abort(.internalServerError) }
        try await SessionSecurity.establishAuthenticated(userID: userID, on: req)
        AuditLogger.log(req: req, action: "login", target: body.username)
        return LoginResponse(twoFactorRequired: false, user: user.toPublic())
    }

    struct ReauthenticateRequest: Content {
        let password: String
        let code: String?
    }

    /// Refresh the short recent-authentication window required by sensitive
    /// account operations. Accounts with 2FA must prove both factors again.
    @Sendable
    func reauthenticate(req: Request) async throws -> HTTPStatus {
        let user = try await req.requireSessionUser()
        let body = try req.content.decode(ReauthenticateRequest.self)
        guard try await req.password.async.verify(body.password, created: user.passwordHash) else {
            throw Abort(.unauthorized, reason: "Invalid credentials.")
        }
        if user.totpEnabled {
            guard let code = body.code,
                  try await TwoFactorController.verifySecondFactor(code, user: user, db: req.db) else {
                throw Abort(.unauthorized, reason: "A valid two-factor code is required.")
            }
        }
        SessionSecurity.markReauthenticated(on: req)
        AuditLogger.log(req: req, action: "reauthenticate", target: user.username)
        return .noContent
    }

    @Sendable
    func logout(req: Request) async throws -> HTTPStatus {
        req.session.destroy()
        return .noContent
    }

    @Sendable
    func me(req: Request) async throws -> User.Public {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }
        return user.toPublic()
    }

    @Sendable
    func setWebhook(req: Request) async throws -> User.Public {
        struct Body: Content { var webhookURL: String? }
        let user = try await req.requireRecentSessionUser()
        let body = try req.content.decode(Body.self)
        let url = body.webhookURL?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url, !url.isEmpty {
            try validateWebhookURL(url)
        }
        user.webhookURL = (url?.isEmpty == false) ? url : nil
        try await user.save(on: req.db)
        AuditLogger.log(req: req, action: "update_webhook", target: user.username)
        return user.toPublic()
    }
    @Sendable
    func setRetention(req: Request) async throws -> User.Public {
        let user = try await req.requireSessionUser()
        struct Body: Content { let retentionDays: Int? }
        let body = try req.content.decode(Body.self)
        if let days = body.retentionDays {
            guard days == 30 || days == 90 || days == 365 else {
                throw Abort(.badRequest, reason: "Retention must be 30, 90, or 365 days (or null to disable).")
            }
        }
        user.retentionDays = body.retentionDays
        try await user.save(on: req.db)
        AuditLogger.log(req: req, action: "update_retention", target: user.username)
        return user.toPublic()
    }

    @Sendable
    func updateSettings(req: Request) async throws -> User.Public {
        let user = try await req.requireRecentSessionUser()
        struct Body: Content {
            let discordWebhookURL: String?
            let telegramBotToken: String?
            let telegramChatID: String?
            let slackWebhookURL: String?
            let verboseAlerts: Bool?
        }
        let body = try req.content.decode(Body.self)
        if let url = body.discordWebhookURL, !url.isEmpty { try validateWebhookURL(url) }
        if let url = body.slackWebhookURL, !url.isEmpty { try validateWebhookURL(url) }
        user.discordWebhookURL = body.discordWebhookURL.map { $0.isEmpty ? nil : $0 } ?? user.discordWebhookURL
        if let rawToken = body.telegramBotToken {
            if rawToken.isEmpty {
                user.telegramBotToken = nil
            } else {
                // Telegram bot tokens follow `<bot_id>:<secret>` — digits, a
                // colon, then 30+ chars of [A-Za-z0-9_-]. Rejecting arbitrary
                // strings up front prevents accidental misconfiguration (e.g.
                // a user pasting their password) and stops anything weird
                // from ending up substituted into the Telegram API URL.
                guard rawToken.range(of: "^[0-9]+:[A-Za-z0-9_-]{30,}$", options: .regularExpression) != nil,
                      rawToken.count <= 100 else {
                    throw Abort(.badRequest, reason: "Telegram bot token format is invalid (expected `<id>:<secret>`).")
                }
                // The model accessor encrypts every notification credential,
                // including Telegram, Discord, Slack, and generic webhooks.
                user.telegramBotToken = rawToken
            }
        }
        user.telegramChatID = body.telegramChatID.map { $0.isEmpty ? nil : $0 } ?? user.telegramChatID
        user.slackWebhookURL = body.slackWebhookURL.map { $0.isEmpty ? nil : $0 } ?? user.slackWebhookURL
        if let verbose = body.verboseAlerts { user.verboseAlerts = verbose }
        try await user.save(on: req.db)
        AuditLogger.log(req: req, action: "update_settings", target: user.username)
        return user.toPublic()
    }

    @Sendable
    func testNotifications(req: Request) async throws -> HTTPStatus {
        let user = try await req.requireSessionUser()
        await NotificationDispatcher.notify(
            user: user,
            title: "Test Notification",
            message: "Your notification channels are configured correctly.",
            scanID: nil,
            app: req.application
        )
        return .ok
    }
}

// MARK: - Helper: extract current user from session (used in other controllers)
extension Request {
    func currentUser() async throws -> User? {
        guard let userID = authenticatedUserID else { return nil }
        return try await User.find(userID, on: db)
    }
}

// MARK: - Webhook URL validation (SSRF prevention)

/// Validates that a webhook URL is an HTTPS URL pointing to a public host.
/// Throws `.badRequest` if the URL is invalid or targets a private/internal range.
private func validateWebhookURL(_ rawURL: String) throws {
    guard let url = URL(string: rawURL),
          let scheme = url.scheme?.lowercased(),
          scheme == "https"
    else {
        throw Abort(.badRequest, reason: "Webhook URL must be a valid HTTPS URL.")
    }
    guard !SSRFGuard.isInternalURL(url) else {
        throw Abort(.badRequest, reason: "Webhook URL must not target an internal or private host.")
    }
    // Resolve the host now and reject names that point at internal space. This
    // is best-effort (DNS can change after save — the outbound SafeHTTP path
    // re-checks at delivery time), but it catches the obvious cases up front.
    guard let host = url.host, !SSRFGuard.resolvesToInternal(host) else {
        throw Abort(.badRequest, reason: "Webhook URL must not resolve to an internal or private host.")
    }
}
