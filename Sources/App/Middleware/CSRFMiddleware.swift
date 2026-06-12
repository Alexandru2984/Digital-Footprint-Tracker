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
        // Compare the parsed *host* exactly, not a string prefix. A prefix check
        // (`origin.hasPrefix("https://swift.micutu.com")`) is defeated by an
        // attacker origin like `https://swift.micutu.com.evil.com`. A request
        // whose Origin/Referer is present but unparseable (e.g. the literal
        // "null" from a sandboxed iframe) yields no host and is rejected.
        let allowedHost = URL(string: Environment.get("ALLOWED_ORIGIN") ?? "https://swift.micutu.com")?.host
            ?? "swift.micutu.com"
        let allowedHosts: Set<String> = [allowedHost, "localhost", "127.0.0.1"]
        guard let originHost = URL(string: origin)?.host, allowedHosts.contains(originHost) else {
            throw Abort(.forbidden, reason: "Cross-origin request blocked.")
        }
        return try await next.respond(to: request)
    }
}
