import Vapor

/// Deny-by-default route authorization for stateless API keys. Browser sessions
/// bypass this layer and retain the normal owner/admin checks in controllers.
/// Any new route is inaccessible to API keys until it is deliberately classified.
struct APIKeyScopeMiddleware: AsyncMiddleware {
    private enum Decision {
        case allowPublic
        case require(APIKey.Scope)
        case deny
    }

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        guard let authorization = request.apiKeyAuthorization else {
            return try await next.respond(to: request)
        }

        switch Self.decision(for: request) {
        case .allowPublic:
            break
        case .require(let scope):
            guard authorization.scopes.contains(scope) else {
                throw Abort(.forbidden, reason: "API key lacks required scope: \(scope.rawValue).")
            }
        case .deny:
            throw Abort(.forbidden, reason: "API keys are not permitted for this endpoint.")
        }
        return try await next.respond(to: request)
    }

    private static func decision(for request: Request) -> Decision {
        let parts = request.url.path.split(separator: "/").map(String.init)
        guard let first = parts.first else { return .allowPublic }

        // Public, non-account endpoints remain public even when a client sends
        // a valid key. /metrics is excluded earlier because it has its own token.
        if request.method == .GET, ["health", "plugins", "openapi.yaml"].contains(first) {
            return .allowPublic
        }
        if first == "share" || first == "geolocate" { return .allowPublic }

        // Account control-plane and administrator routes are browser-session-only.
        if first == "account" || first == "admin" { return .deny }
        if first == "auth" {
            return request.method == .GET && parts == ["auth", "me"]
                ? .require(.scansRead) : .deny
        }

        if first == "scan" { return .require(.scansWrite) }
        if first == "results" || first == "stream" || first == "my-scans" {
            return .require(.scansRead)
        }
        if ["stats", "export", "report", "identity", "correlations"].contains(first) {
            return .require(.scansRead)
        }
        if first == "scans" {
            return request.method == .GET ? .require(.scansRead) : .require(.scansWrite)
        }
        if first == "shares" { return .require(.scansWrite) }
        if first == "tags" {
            return request.method == .GET ? .require(.scansRead) : .require(.scansWrite)
        }
        if first == "scheduled-scans" {
            return request.method == .GET ? .require(.automationRead) : .require(.automationWrite)
        }
        if first == "notifications" {
            return request.method == .GET ? .require(.automationRead) : .require(.automationWrite)
        }
        if first == "investigations" {
            return request.method == .GET ? .require(.investigationsRead) : .require(.investigationsWrite)
        }
        // High-risk dark-web collection is deliberately interactive-session
        // only for the initial release; API keys cannot acknowledge operator
        // authorization or satisfy the tighter abuse controls.
        if first == "dark-web" { return .deny }

        return .deny
    }
}
