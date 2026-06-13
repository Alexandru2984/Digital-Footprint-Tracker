import Vapor
import Fluent

/// GET /identity/:id — a synthesized identity profile for a scan (names, emails,
/// handles, confirmed accounts, breaches, …). Same ownership rules as the raw
/// results: the owner only; anonymous scans are admin-only.
struct IdentityController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.grouped(NoCacheMiddleware()).get("identity", ":id", use: getIdentity)
    }

    @Sendable
    func getIdentity(req: Request) async throws -> IdentitySynthesizer.IdentityProfile {
        guard let idString = req.parameters.get("id"), let id = UUID(uuidString: idString) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db)
            .filter(\.$id == id)
            .with(\.$results)
            .first() else {
            throw Abort(.notFound, reason: "Scan not found.")
        }

        try await scan.authorizeRead(req)
        return scan.synthesizedIdentity()
    }
}
