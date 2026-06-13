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

        if let ownerID = scan.$user.id {
            guard let me = try await req.currentUser(), me.id == ownerID else {
                throw Abort(.forbidden, reason: "Access denied.")
            }
        } else {
            guard let me = try await req.currentUser(), me.isAdmin else {
                throw Abort(.forbidden, reason: "Access denied.")
            }
        }

        let risk = RiskScorer.compute(results: scan.results)
        let inputs = scan.results.map {
            IdentitySynthesizer.Input(
                source: $0.source,
                type: $0.type,
                confidence: $0.confidenceScore,
                metadata: $0.metadataObject ?? [:],
                rawData: $0.rawData
            )
        }
        return IdentitySynthesizer.synthesize(from: inputs, riskScore: risk.value, riskLevel: risk.level.rawValue)
    }
}
