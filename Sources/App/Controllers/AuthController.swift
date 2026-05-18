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
        auth.post("logout", use: logout)
        auth.get("me", use: me)
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

        // Regenerate session to prevent session fixation: clear any pre-auth data
        // before binding the authenticated user ID to this session.
        req.session.data = .init()
        req.session.data["userID"] = user.id?.uuidString

        return user.toPublic()
    }

    @Sendable
    func login(req: Request) async throws -> User.Public {
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

        // Regenerate session to prevent session fixation.
        req.session.data = .init()
        req.session.data["userID"] = user.id?.uuidString
        AuditLogger.log(req: req, action: "login", target: body.username)
        return user.toPublic()
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
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }
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
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
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
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
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
        // Encrypt Telegram token at rest. Behaviour matters:
        //   • ENCRYPTION_KEY set + encrypt() succeeds  → store ciphertext (normal path)
        //   • ENCRYPTION_KEY set + encrypt() throws    → 500, do NOT save (fail closed)
        //   • ENCRYPTION_KEY missing entirely          → operator opt-out; store raw
        // The previous `(try? encrypt) ?? raw` silently saved plaintext when
        // the key was set but malformed — fail-open behaviour that defeats
        // the at-rest encryption guarantee.
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
                if TokenEncryption.isAvailable() {
                    do {
                        user.telegramBotToken = try TokenEncryption.encrypt(rawToken)
                    } catch {
                        req.logger.error("TokenEncryption.encrypt failed for user \(user.id?.uuidString ?? "?"): \(error)")
                        throw Abort(.internalServerError, reason: "Failed to encrypt sensitive setting; nothing saved.")
                    }
                } else {
                    user.telegramBotToken = rawToken
                }
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
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
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
}
