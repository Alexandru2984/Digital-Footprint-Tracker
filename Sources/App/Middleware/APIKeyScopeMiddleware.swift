import Vapor

/// Deny-by-default route authorization for stateless API keys. Browser sessions
/// bypass this layer and retain the normal owner/admin checks in controllers.
/// Any new route is inaccessible to API keys until it is deliberately classified.
struct APIKeyScopeMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        guard let authorization = request.apiKeyAuthorization else {
            return try await next.respond(to: request)
        }

        let path = request.url.path.split(separator: "/").map(String.init)
        switch APIKeyRoutePolicy.decision(method: request.method, pathComponents: path) {
        case .allowPublic:
            break
        case .require(let scope):
            guard authorization.scopes.contains(scope) else {
                throw Abort(.forbidden, reason: "API key lacks required scope: \(scope.rawValue).")
            }
        case .deny:
            throw Abort(.forbidden, reason: "API keys are not permitted for this endpoint.")
        case .unclassified:
            throw Abort(.forbidden, reason: "API keys are not permitted for an unclassified endpoint.")
        }
        return try await next.respond(to: request)
    }
}
