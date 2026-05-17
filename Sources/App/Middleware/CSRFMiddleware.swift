import Vapor

/// Defense-in-depth CSRF protection via Origin/Referer header validation.
/// The session cookie uses SameSite=Strict which already prevents most CSRF.
/// This middleware adds a secondary check: state-changing requests that include
/// an Origin or Referer header must originate from the configured site URL.
struct CSRFMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Only check state-changing methods
        guard [.POST, .PUT, .PATCH, .DELETE].contains(request.method) else {
            return try await next.respond(to: request)
        }
        // API key auth (Bearer token) is stateless — not vulnerable to CSRF
        if request.headers.bearerAuthorization != nil {
            return try await next.respond(to: request)
        }
        // If no Origin or Referer header, allow (server-to-server, curl, etc.)
        guard let origin = request.headers.first(name: "Origin")
                         ?? request.headers.first(name: "Referer")
        else {
            return try await next.respond(to: request)
        }
        let allowed = [
            Environment.get("ALLOWED_ORIGIN") ?? "https://swift.micutu.com",
            "http://localhost:8085",
            "http://127.0.0.1:8085"
        ]
        guard allowed.contains(where: { origin.hasPrefix($0) }) else {
            throw Abort(.forbidden, reason: "Cross-origin request blocked.")
        }
        return try await next.respond(to: request)
    }
}
