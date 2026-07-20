import Vapor
import Fluent
import Crypto

/// Request-scoped storage key for the authenticated user ID set by Bearer-token auth.
/// Using `req.storage` (per-request) instead of `req.session.data` (in-memory sessions)
/// is critical: it keeps API-key auth fully stateless. Writing to session.data on every
/// Bearer request creates an unbounded in-memory session entry per call and would leak
/// memory under sustained API traffic.
private struct AuthedUserIDStorageKey: StorageKey {
    typealias Value = UUID
}

struct APIKeyAuthorizationContext: Sendable {
    let keyID: UUID
    let scopes: Set<APIKey.Scope>
}

private struct APIKeyAuthorizationStorageKey: StorageKey {
    typealias Value = APIKeyAuthorizationContext
}

extension Request {
    /// User ID resolved by Bearer-token authentication (request-scoped only — does NOT
    /// touch the session store, so each call is stateless).
    var authedUserID: UUID? {
        get { storage[AuthedUserIDStorageKey.self] }
        set { storage[AuthedUserIDStorageKey.self] = newValue }
    }

    var apiKeyAuthorization: APIKeyAuthorizationContext? {
        get { storage[APIKeyAuthorizationStorageKey.self] }
        set { storage[APIKeyAuthorizationStorageKey.self] = newValue }
    }

    /// Unified read for the current authenticated user ID across both auth modes:
    /// cookie-based sessions (set by login/register) and stateless Bearer API keys
    /// (set by `APIKeyMiddleware`). Prefer this over reading `session.data` directly.
    var authenticatedUserID: UUID? {
        if let id = authedUserID { return id }
        if hasSession, let raw = session.data["userID"], let id = UUID(raw) { return id }
        return nil
    }

    /// Privileged account controls must never accept a bearer credential. API
    /// keys are intentionally limited to the data-plane scopes enforced by
    /// `APIKeyScopeMiddleware`.
    func requireSessionUser() async throws -> User {
        guard apiKeyAuthorization == nil, hasSession,
              let raw = session.data["userID"], let userID = UUID(raw),
              let user = try await User.find(userID, on: db) else {
            throw Abort(.unauthorized, reason: "An authenticated browser session is required.")
        }
        return user
    }
}

struct APIKeyMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // /metrics has its own independent bearer credential. Do not interpret
        // METRICS_TOKEN as a user API key.
        if request.method == .GET, request.url.path == "/metrics" {
            return try await next.respond(to: request)
        }
        // Skip when a session is already authenticated (cookie-based login wins).
        // `hasSession` avoids creating and persisting an empty session for every
        // otherwise-stateless bearer request.
        let hasAuthenticatedSession = request.hasSession
            && request.session.data["userID"] != nil
        if !hasAuthenticatedSession, let bearer = request.headers.bearerAuthorization {
            let token = bearer.token.trimmingCharacters(in: .whitespaces)
            guard !token.isEmpty, token.utf8.count <= 512 else {
                throw Abort(.unauthorized, reason: "Invalid API key.")
            }
            let hash = sha256Hex(token)
            guard let apiKey = try await APIKey.query(on: request.db)
                .filter(\.$keyHash == hash).first(),
                  let keyID = apiKey.id,
                  let expiresAt = apiKey.expiresAt, expiresAt > Date() else {
                throw Abort(.unauthorized, reason: "Invalid or expired API key.")
            }

            // Stateless: attach identity + authorization to request storage only.
            request.authedUserID = apiKey.$user.id
            request.apiKeyAuthorization = .init(keyID: keyID, scopes: apiKey.scopes)

            // Debounce the lastUsedAt touch: at most one write per minute per key.
            let now = Date()
            let shouldTouch = apiKey.lastUsedAt.map { now.timeIntervalSince($0) > 60 } ?? true
            if shouldTouch {
                let db = request.application.db
                Task {
                    try? await APIKey.query(on: db)
                        .filter(\.$id == keyID)
                        .set(\.$lastUsedAt, to: now)
                        .update()
                }
            }
        } else if !hasAuthenticatedSession,
                  let authorization = request.headers.first(name: .authorization),
                  authorization.lowercased().hasPrefix("bearer") {
            // Do not silently downgrade malformed bearer requests to anonymous.
            throw Abort(.unauthorized, reason: "Malformed bearer authorization.")
        }
        return try await next.respond(to: request)
    }
}
