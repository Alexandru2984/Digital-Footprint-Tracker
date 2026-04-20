import Vapor
import Fluent

struct ScanRequest: Content {
    let input: String
}

struct ScanResponse: Content {
    let scanID: UUID
    let input: String
    let results: [Result]
}

struct ScanController: RouteCollection {
    let plugins: [FootprintPlugin] = [
        GravatarPlugin(),
        UsernamePlugin(),
        BulkUsernamePlugin() // Added Bulk OSINT Plugin
    ]
    
    func boot(routes: RoutesBuilder) throws {
        routes.post("scan", use: scan)
        routes.get("results", ":id", use: getResults)
    }

    @Sendable
    func scan(req: Request) async throws -> ScanResponse {
        let scanReq = try req.content.decode(ScanRequest.self)
        
        // Check if scan already exists
        if let existingScan = try await Scan.query(on: req.db)
            .filter(\.$input == scanReq.input)
            .with(\.$results)
            .first() {
            return ScanResponse(scanID: existingScan.id!, input: existingScan.input, results: existingScan.results)
        }
        
        let newScan = Scan(input: scanReq.input)
        try await newScan.save(on: req.db)
        guard let scanID = newScan.id else {
            throw Abort(.internalServerError)
        }
        
        let app = req.application
        let inputString = scanReq.input
        let activePlugins = self.plugins
        
        // Run actual plugins asynchronously in the background so the HTTP request completes immediately
        Task {
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
                    app.logger.error("Plugin \(plugin.name) failed: \(error)")
                }
            }
        }

        return ScanResponse(scanID: scanID, input: scanReq.input, results: [])
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
        
        return ScanResponse(scanID: scan.id!, input: scan.input, results: scan.results)
    }
}
