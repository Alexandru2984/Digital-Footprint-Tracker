import Vapor
import Fluent

struct ScanRequest: Content {
    let input: String
}

struct ScanResponse: Content {
    let scanID: UUID
    let input: String
    let status: String
    let results: [Result]
}

struct ScanController: RouteCollection {
    let plugins: [FootprintPlugin] = [
        GravatarPlugin(),
        UsernamePlugin(),
        BulkUsernamePlugin(),
        BulkEmailPlugin()
    ]

    func boot(routes: RoutesBuilder) throws {
        routes.grouped(ScanRateLimiter()).post("scan", use: scan)
        routes.get("results", ":id", use: getResults)
    }

    @Sendable
    func scan(req: Request) async throws -> ScanResponse {
        let scanReq = try req.content.decode(ScanRequest.self)

        // Reuse prior non-failed scans; re-run if the last attempt failed.
        if let existingScan = try await Scan.query(on: req.db)
            .filter(\.$input == scanReq.input)
            .filter(\.$statusRaw != ScanStatus.failed.rawValue)
            .with(\.$results)
            .first() {
            return ScanResponse(
                scanID: existingScan.id!,
                input: existingScan.input,
                status: existingScan.status.rawValue,
                results: existingScan.results
            )
        }

        let newScan = Scan(input: scanReq.input)
        try await newScan.save(on: req.db)
        guard let scanID = newScan.id else {
            throw Abort(.internalServerError)
        }

        let app = req.application
        let inputString = scanReq.input
        let activePlugins = self.plugins

        // Run plugins in the background so the HTTP request returns immediately.
        Task {
            var anyFailure = false
            for plugin in activePlugins {
                do {
                    let pluginResults = try await plugin.scan(input: inputString, on: app)
                    for pr in pluginResults {
                        let result = Result(
                            scanID: scanID,
                            source: pr.source,
                            type: pr.type,
                            confidenceScore: pr.confidenceScore,
                            rawData: pr.rawData
                        )
                        try await result.save(on: app.db)
                    }
                } catch {
                    anyFailure = true
                    app.logger.error("Plugin \(plugin.name) failed: \(error)")
                }
            }

            do {
                if let scan = try await Scan.find(scanID, on: app.db) {
                    scan.status = anyFailure ? .failed : .completed
                    scan.completedAt = Date()
                    try await scan.save(on: app.db)
                }
            } catch {
                app.logger.error("Failed to mark scan \(scanID) as finished: \(error)")
            }
        }

        return ScanResponse(scanID: scanID, input: scanReq.input, status: newScan.status.rawValue, results: [])
    }

    @Sendable
    func getResults(req: Request) async throws -> ScanResponse {
        guard let idString = req.parameters.get("id"), let id = UUID(uuidString: idString) else {
            throw Abort(.badRequest, reason: "Invalid ID")
        }

        guard let scan = try await Scan.query(on: req.db)
            .filter(\.$id == id)
            .with(\.$results)
            .first() else {
            throw Abort(.notFound, reason: "Scan not found")
        }

        return ScanResponse(
            scanID: scan.id!,
            input: scan.input,
            status: scan.status.rawValue,
            results: scan.results
        )
    }
}
