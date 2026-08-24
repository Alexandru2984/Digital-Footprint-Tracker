import Fluent
import Vapor

/// GET /scans/:scanID/timeline — normalized chronology and aggregate timeline
/// intelligence. It uses the same owner/capability authorization as identity
/// synthesis and never returns raw finding payloads.
struct TimelineController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.grouped(NoCacheMiddleware())
            .get("scans", ":scanID", "timeline", use: getTimeline)
    }

    @Sendable
    func getTimeline(req: Request) async throws -> TimelineIntelligence.Report {
        guard let idString = req.parameters.get("scanID"),
              let id = UUID(uuidString: idString) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db)
            .filter(\.$id == id)
            .with(\.$results)
            .first() else {
            throw Abort(.notFound, reason: "Scan not found.")
        }

        try await scan.authorizeRead(req)
        return try scan.timelineIntelligence()
    }
}
