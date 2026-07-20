import Vapor

/// Central session rotation, lifetime, and recent-authentication policy.
enum SessionSecurity {
    static let absoluteTTL: TimeInterval = 7 * 86_400
    static let idleTTL: TimeInterval = 24 * 3_600
    static let recentAuthenticationTTL: TimeInterval = 10 * 60
    private static let touchInterval: TimeInterval = 5 * 60

    static func establishAuthenticated(userID: UUID, on req: Request) async throws {
        let now = Date().timeIntervalSince1970
        try await rotate(on: req, data: .init(initialData: [
            "userID": userID.uuidString,
            "sessionStartedAt": String(now),
            "lastSeenAt": String(now),
            "authenticatedAt": String(now),
        ]))
    }

    static func establishPendingTwoFactor(userID: UUID, on req: Request) async throws {
        let now = Date().timeIntervalSince1970
        try await rotate(on: req, data: .init(initialData: [
            "pending2FAUserID": userID.uuidString,
            "pending2FAAt": String(now),
        ]))
    }

    /// Delete the old server-side row before forcing Vapor to mint a fresh ID.
    /// Merely clearing `session.data` leaves the identifier fixed and is not a
    /// defense against session fixation.
    static func rotate(on req: Request, data: SessionData) async throws {
        let oldID = req.hasSession ? req.session.id : nil
        if let oldID {
            try await req.application.sessions.driver.deleteSession(oldID, for: req).get()
        }
        req.session.id = nil
        req.session.data = data
    }

    private static func invalidate(on req: Request) async throws {
        if let oldID = req.session.id {
            try await req.application.sessions.driver.deleteSession(oldID, for: req).get()
        }
        req.session.data = .init()
        req.session.destroy()
    }

    static func markReauthenticated(on req: Request) {
        req.session.data["authenticatedAt"] = String(Date().timeIntervalSince1970)
    }

    static func isRecent(_ req: Request, now: Date = Date()) -> Bool {
        guard req.hasSession,
              let raw = req.session.data["authenticatedAt"],
              let timestamp = TimeInterval(raw) else { return false }
        let age = now.timeIntervalSince1970 - timestamp
        return age >= 0 && age <= recentAuthenticationTTL
    }

    fileprivate static func validateAndTouch(_ req: Request, now: Date = Date()) async throws {
        guard req.hasSession else { return }
        let canEstablishSession = req.method == .POST
            && ["/auth/login", "/auth/register"].contains(req.url.path)

        // Vapor materializes an empty, id-less Session when an attacker sends
        // an unknown cookie. Destroy it so arbitrary cookie values cannot force
        // one new database row per request. Login/register are the exception:
        // they need the valid in-request container to establish a new session.
        if req.session.id == nil, req.session.data.snapshot.isEmpty {
            if !canEstablishSession { req.session.destroy() }
            return
        }

        guard req.session.data["userID"] != nil else { return }
        let epoch = now.timeIntervalSince1970
        guard let startedRaw = req.session.data["sessionStartedAt"],
              let lastSeenRaw = req.session.data["lastSeenAt"],
              let started = TimeInterval(startedRaw),
              let lastSeen = TimeInterval(lastSeenRaw),
              epoch >= started, epoch >= lastSeen,
              epoch - started <= absoluteTTL,
              epoch - lastSeen <= idleTTL else {
            if canEstablishSession {
                // Let a login request carrying an expired cookie recover in one
                // round trip, but ensure it cannot retain the old identifier.
                try await rotate(on: req, data: .init())
            } else {
                try await invalidate(on: req)
            }
            return
        }
        if epoch - lastSeen >= touchInterval {
            req.session.data["lastSeenAt"] = String(epoch)
        }
    }
}

struct SessionSecurityMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        try await SessionSecurity.validateAndTouch(request)
        return try await next.respond(to: request)
    }
}

extension Request {
    func requireRecentSessionUser() async throws -> User {
        let user = try await requireSessionUser()
        guard SessionSecurity.isRecent(self) else {
            throw Abort(.unauthorized, reason: "Recent authentication is required for this operation.")
        }
        return user
    }
}
