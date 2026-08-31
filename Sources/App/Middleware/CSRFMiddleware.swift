import Vapor

/// Defense-in-depth CSRF protection for state-changing requests.
///
/// Browser sessions use a `SameSite=Strict` cookie, but the server still validates
/// request provenance. Only a successfully authenticated API key is exempt; the
/// mere presence of an `Authorization` header must never disable CSRF checks.
struct CSRFMiddleware: AsyncMiddleware {
    private let requireProvenanceForSessions: Bool?

    /// The override exists so the production-only missing-header policy can be
    /// exercised by the test application without weakening normal test fixtures.
    init(requireProvenanceForSessions: Bool? = nil) {
        self.requireProvenanceForSessions = requireProvenanceForSessions
    }

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        guard [.POST, .PUT, .PATCH, .DELETE].contains(request.method) else {
            return try await next.respond(to: request)
        }

        // A validated, scoped API key is stateless and cannot be sent ambiently
        // by a browser. APIKeyMiddleware has already populated this context.
        if request.apiKeyAuthorization != nil {
            return try await next.respond(to: request)
        }

        if request.headers.first(name: "Sec-Fetch-Site")?.lowercased() == "cross-site" {
            throw Abort(.forbidden, reason: "Cross-origin request blocked.")
        }

        let provenance = request.headers.first(name: "Origin")
            ?? request.headers.first(name: "Referer")

        if let provenance {
            guard Self.isAllowed(provenance, for: request.application.environment) else {
                throw Abort(.forbidden, reason: "Cross-origin request blocked.")
            }
        } else {
            let hasAmbientAuthenticatedSession = request.hasSession
                && (request.session.data["userID"] != nil
                    || request.session.data["pending2FAUserID"] != nil)
            let requireProvenance = requireProvenanceForSessions
                ?? request.application.environment.isRealDeployment
            if requireProvenance && hasAmbientAuthenticatedSession {
                throw Abort(.forbidden, reason: "Request provenance is required.")
            }
        }

        return try await next.respond(to: request)
    }

    private struct NormalizedOrigin: Hashable {
        let scheme: String
        let host: String
        let port: Int

        init?(_ rawValue: String) {
            guard let url = URL(string: rawValue),
                  let scheme = url.scheme?.lowercased(),
                  let host = url.host?.lowercased(),
                  scheme == "https" || scheme == "http" else {
                return nil
            }
            let defaultPort = scheme == "https" ? 443 : 80
            self.scheme = scheme
            self.host = host
            self.port = url.port ?? defaultPort
        }
    }

    private static func isAllowed(_ rawOriginOrReferer: String, for environment: Environment) -> Bool {
        guard let candidate = NormalizedOrigin(rawOriginOrReferer) else { return false }
        let configured = Environment.get("ALLOWED_ORIGIN") ?? "https://swift.micutu.com"
        guard let allowed = NormalizedOrigin(configured) else { return false }

        if candidate == allowed { return true }

        // Local front-end dev servers may use arbitrary ports. This exception is
        // deliberately unavailable in any real deployment, not merely in one
        // named `production`.
        return !environment.isRealDeployment
            && (candidate.host == "localhost" || candidate.host == "127.0.0.1")
    }
}
