import Fluent
import Vapor

/// GET /scans/:scanID/timeline — normalized chronology and aggregate timeline
/// intelligence. It uses the same owner/capability authorization as identity
/// synthesis and never returns raw finding payloads.
struct TimelineController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.grouped(NoCacheMiddleware())
            .grouped(ScanRateLimiter(anonMax: 20, authedMax: 120, windowSeconds: 60))
            .get("scans", ":scanID", "timeline", use: getTimeline)
    }

    @Sendable
    func getTimeline(req: Request) async throws -> TimelineIntelligence.Report {
        let scan = try await Scan.readableWithResults(req, parameter: "scanID")
        return try scan.timelineIntelligence()
    }
}
