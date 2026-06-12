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

extension Request {
    /// User ID resolved by Bearer-token authentication (request-scoped only — does NOT
    /// touch the session store, so each call is stateless).
    var authedUserID: UUID? {
        get { storage[AuthedUserIDStorageKey.self] }
        set { storage[AuthedUserIDStorageKey.self] = newValue }
    }

    /// Unified read for the current authenticated user ID across both auth modes:
    /// cookie-based sessions (set by login/register) and stateless Bearer API keys
    /// (set by `APIKeyMiddleware`). Prefer this over reading `session.data` directly.
    var authenticatedUserID: UUID? {
        if let id = authedUserID { return id }
        if let raw = session.data["userID"], let id = UUID(raw) { return id }
        return nil
    }
}

struct APIKeyMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Skip when a session is already authenticated (cookie-based login wins).
        if request.session.data["userID"] == nil,
           let authHeader = request.headers[.authorization].first,
           authHeader.hasPrefix("Bearer ") {
            let token = String(authHeader.dropFirst("Bearer ".count)).trimmingCharacters(in: .whitespaces)
            if !token.isEmpty {
                let hash = sha256Hex(token)
                if let apiKey = try? await APIKey.query(on: request.db).filter(\.$keyHash == hash).first() {
                    // Stateless: attach to request storage only — no session write.
                    request.authedUserID = apiKey.$user.id
                    // Debounce the lastUsedAt touch: at most one write per minute
                    // per key. Previously this fired a detached find+save on EVERY
                    // authenticated request — a DB write per read, unbounded under
                    // sustained API traffic. A targeted UPDATE also avoids the
                    // redundant re-fetch of a row already in hand.
                    let now = Date()
                    let shouldTouch = apiKey.lastUsedAt.map { now.timeIntervalSince($0) > 60 } ?? true
                    if shouldTouch, let keyID = apiKey.id {
                        let db = request.application.db
                        Task {
                            try? await APIKey.query(on: db)
                                .filter(\.$id == keyID)
                                .set(\.$lastUsedAt, to: now)
                                .update()
                        }
                    }
                }
            }
        }
        return try await next.respond(to: request)
    }
}
