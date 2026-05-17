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

        guard let user = try await User.query(on: req.db)
            .filter(\.$username == body.username)
            .first()
        else {
            throw Abort(.unauthorized, reason: "Invalid username or password.")
        }

        let valid = try await req.password.async.verify(body.password, created: user.passwordHash)
        guard valid else {
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
        }
        let body = try req.content.decode(Body.self)
        if let url = body.discordWebhookURL, !url.isEmpty { try validateWebhookURL(url) }
        if let url = body.slackWebhookURL, !url.isEmpty { try validateWebhookURL(url) }
        user.discordWebhookURL = body.discordWebhookURL.map { $0.isEmpty ? nil : $0 } ?? user.discordWebhookURL
        // Encrypt Telegram token at rest if encryption key is configured
        if let rawToken = body.telegramBotToken {
            if rawToken.isEmpty {
                user.telegramBotToken = nil
            } else {
                user.telegramBotToken = (try? TokenEncryption.encrypt(rawToken)) ?? rawToken
            }
        }
        user.telegramChatID = body.telegramChatID.map { $0.isEmpty ? nil : $0 } ?? user.telegramChatID
        user.slackWebhookURL = body.slackWebhookURL.map { $0.isEmpty ? nil : $0 } ?? user.slackWebhookURL
        try await user.save(on: req.db)
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
