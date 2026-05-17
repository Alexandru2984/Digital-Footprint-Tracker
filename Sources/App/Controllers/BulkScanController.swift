import Vapor
import Fluent

struct BulkScanController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.grouped(ScanRateLimiter()).post("scan", "bulk", use: bulkScan)
    }

    struct BulkScanRequest: Content {
        let targets: [String]
        let plugins: [String]?
    }

    struct BulkScanResult: Content {
        let target: String
        let scanID: String
        let status: String
    }

    @Sendable
    func bulkScan(req: Request) async throws -> [BulkScanResult] {
        // Bulk scanning requires authentication to prevent abuse.
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Authentication required for bulk scan.")
        }

        let body = try req.content.decode(BulkScanRequest.self)
        guard !body.targets.isEmpty else {
            throw Abort(.badRequest, reason: "targets array must not be empty")
        }
        guard body.targets.count <= 50 else {
            throw Abort(.badRequest, reason: "Maximum 50 targets per bulk scan")
        }
        // Apply the same SSRF + charset + length checks as `/scan`. Previously
        // BulkScan only ran SSRFGuard on the raw target, leaving the character
        // whitelist behind — an authenticated user could submit shell or HTML
        // metacharacters that reached plugin URL templates and subprocess argv.
        // The validator also returns canonical normalized form (email-lowercase).
        var targets: [String] = []
        targets.reserveCapacity(body.targets.count)
        for raw in body.targets {
            // InputValidator.validateScanInput throws a generic 400 — does NOT
            // echo the offending target back in the reason, so the error
            // response is safe to render in any context.
            targets.append(try InputValidator.validateScanInput(raw))
        }

        let userID = user.id
        let app = req.application

        let requestedPlugins = body.plugins?.map { $0.lowercased() } ?? []
        let activePlugins: [any FootprintPlugin]
        if requestedPlugins.isEmpty {
            activePlugins = ScanController.defaultPlugins
        } else {
            activePlugins = ScanController.defaultPlugins.filter { requestedPlugins.contains($0.name.lowercased()) }
            guard !activePlugins.isEmpty else {
                throw Abort(.badRequest, reason: "No valid plugins specified")
            }
        }

        var results: [BulkScanResult] = []

        for target in targets {
            let scan = Scan(input: target, userID: userID)
            try await scan.save(on: req.db)
            guard let scanID = scan.id else { continue }
            AuditLogger.log(req: req, action: "bulk_scan_start", target: String(target.prefix(100)))

            let pluginsCopy = activePlugins
            Task {
                await ScanPluginRunner.run(scanID: scanID, input: target, plugins: pluginsCopy, app: app)
            }

            results.append(BulkScanResult(target: target, scanID: scanID.uuidString, status: "pending"))
        }

        return results
    }
}
