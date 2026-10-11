import Vapor
import Fluent

/// GET /identity/:id — a synthesized identity profile for a scan (names, emails,
/// handles, confirmed accounts, breaches, …). Same ownership rules as the raw
/// results: the owner only; anonymous scans are admin-only.
struct IdentityController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.grouped(NoCacheMiddleware())
              .grouped(ScanRateLimiter(anonMax: 20, authedMax: 120, windowSeconds: 60))
              .get("identity", ":id", use: getIdentity)
    }

    @Sendable
    func getIdentity(req: Request) async throws -> IdentitySynthesizer.IdentityProfile {
        let scan = try await Scan.readableWithResults(req)
        return try scan.synthesizedIdentity()
    }
}
