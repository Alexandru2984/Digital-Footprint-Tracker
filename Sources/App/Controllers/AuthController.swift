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
        auth.post("register", use: register)
        auth.post("login", use: login)
        auth.post("logout", use: logout)
        auth.get("me", use: me)
        auth.post("webhook", use: setWebhook)
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

        // Check uniqueness
        let existingUsername = try await User.query(on: req.db).filter(\.$username == body.username).first()
        if existingUsername != nil {
            throw Abort(.conflict, reason: "Username already taken.")
        }
        let existingEmail = try await User.query(on: req.db).filter(\.$email == body.email.lowercased()).first()
        if existingEmail != nil {
            throw Abort(.conflict, reason: "Email already registered.")
        }

        let hash = try await req.password.async.hash(body.password)
        let user = User(username: body.username, email: body.email.lowercased(), passwordHash: hash)
        try await user.save(on: req.db)

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
        return user.toPublic()
    }

    @Sendable
    func logout(req: Request) async throws -> HTTPStatus {
        req.session.destroy()
        return .noContent
    }

    @Sendable
    func me(req: Request) async throws -> User.Public {
        guard let userIDString = req.session.data["userID"],
              let userID = UUID(userIDString),
              let user = try await User.find(userID, on: req.db)
        else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }
        return user.toPublic()
    }

    @Sendable
    func setWebhook(req: Request) async throws -> User.Public {
        struct Body: Content { var webhookURL: String? }
        guard let userIDString = req.session.data["userID"],
              let userID = UUID(userIDString),
              let user = try await User.find(userID, on: req.db)
        else {
            throw Abort(.unauthorized, reason: "Not authenticated.")
        }
        let body = try req.content.decode(Body.self)
        let url = body.webhookURL?.trimmingCharacters(in: .whitespacesAndNewlines)
        user.webhookURL = (url?.isEmpty == false) ? url : nil
        try await user.save(on: req.db)
        return user.toPublic()
    }
}

// MARK: - Helper: extract current user from session (used in other controllers)
extension Request {
    func currentUser() async throws -> User? {
        guard let userIDString = session.data["userID"],
              let userID = UUID(userIDString)
        else { return nil }
        return try await User.find(userID, on: db)
    }
}
