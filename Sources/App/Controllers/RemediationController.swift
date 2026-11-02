import Fluent
import Vapor

/// GET /scans/:scanID/remediation — the scan's security findings as a
/// prioritised fix list (see `Remediation`). Same owner/capability
/// authorization as the timeline and identity views.
struct RemediationController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.grouped(NoCacheMiddleware())
            .grouped(ScanRateLimiter(anonMax: 20, authedMax: 120, windowSeconds: 60))
            .get("scans", ":scanID", "remediation", use: getFixes)
    }

    @Sendable
    func getFixes(req: Request) async throws -> [Remediation.Fix] {
        let scan = try await Scan.readableWithResults(req, parameter: "scanID")
        return try Remediation.fixes(for: scan.results)
    }
}
