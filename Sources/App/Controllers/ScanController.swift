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
    let plugins: [any FootprintPlugin] = [
        GravatarPlugin(),
        HaveIBeenPwnedPlugin(),
        UsernamePlugin(),
        BulkUsernamePlugin(),
        BulkEmailPlugin()
    ]

    func boot(routes: RoutesBuilder) throws {
        routes.grouped(ScanRateLimiter()).post("scan", use: scan)
        // Results can be polled frequently but still need protection against abuse.
        routes.grouped(ScanRateLimiter(maxRequests: 60, windowSeconds: 60)).get("results", ":id", use: getResults)
    }

    @Sendable
    func scan(req: Request) async throws -> ScanResponse {
        let scanReq = try req.content.decode(ScanRequest.self)

        let input = scanReq.input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty else {
            throw Abort(.badRequest, reason: "Input cannot be empty.")
        }
        guard input.count <= 255 else {
            throw Abort(.badRequest, reason: "Input must be 255 characters or fewer.")
        }
        // Allow only printable ASCII that makes sense for an email or username.
        // This blocks control characters, null bytes, and anything that could
        // manipulate URLs in BulkUsernamePlugin or shell args in BulkEmailPlugin.
        let allowedCharacters = CharacterSet.alphanumerics
            .union(.init(charactersIn: "@._+-"))
        guard input.unicodeScalars.allSatisfy({ allowedCharacters.contains($0) }) else {
            throw Abort(.badRequest, reason: "Input contains invalid characters.")
        }

        // Audit log: record every scan request with client IP for later review.
        let clientIP = req.headers.first(name: "CF-Connecting-IP")
            ?? req.headers.first(name: "X-Real-IP")
            ?? req.remoteAddress?.description
            ?? "unknown"
        req.logger.info("Scan requested: input=\(input) ip=\(clientIP)")

        // Reuse the most recent non-failed scan; re-run only if the last attempt failed.
        if let existingScan = try await Scan.query(on: req.db)
            .filter(\.$input == input)
            .filter(\.$statusRaw != ScanStatus.failed.rawValue)
            .with(\.$results)
            .sort(\.$createdAt, .descending)
            .first() {
            return ScanResponse(
                scanID: existingScan.id!,
                input: existingScan.input,
                status: existingScan.status.rawValue,
                results: existingScan.results
            )
        }

        let newScan = Scan(input: input)
        try await newScan.save(on: req.db)
        guard let scanID = newScan.id else {
            throw Abort(.internalServerError)
        }

        let app = req.application
        let activePlugins = self.plugins

        // Run plugins in the background so the HTTP request returns immediately.
        // A 120-second deadline prevents scans from hanging in "pending" forever
        // if a plugin stalls or a remote server never responds.
        Task {
            // Use the optional-returning API so we exit gracefully if the app
            // shuts down (e.g., during tests) before this Task gets a chance to run.
            guard let db = app.databases.database(
                nil, logger: app.logger, on: app.eventLoopGroup.any()
            ) else {
                app.logger.warning("Scan \(scanID): database unavailable, skipping plugin execution")
                return
            }

            var successCount = 0
            var failureCount = 0
            var timedOut = false

            enum PluginOutcome { case success, failure, timeout }

            await withTaskGroup(of: PluginOutcome.self) { group in
                // Timeout sentinel: cancels all plugins if 120 s elapse.
                group.addTask {
                    try? await Task.sleep(for: .seconds(120))
                    return .timeout
                }

                // Each plugin runs concurrently in its own child task.
                for plugin in activePlugins {
                    group.addTask {
                        guard !Task.isCancelled else { return .failure }
                        do {
                            let pluginResults = try await plugin.scan(input: input, on: app)
                            for pr in pluginResults {
                                let result = Result(
                                    scanID: scanID,
                                    source: pr.source,
                                    type: pr.type,
                                    confidenceScore: pr.confidenceScore,
                                    rawData: pr.rawData
                                )
                                try await result.save(on: db)
                            }
                            return .success
                        } catch {
                            app.logger.error("Plugin \(plugin.name) failed: \(error)")
                            return .failure
                        }
                    }
                }

                // Drain results. Cancel remaining tasks as soon as all plugins
                // have responded (killing the timeout sentinel) or on timeout.
                var pluginsDone = 0
                var allPluginsCompleted = false
                for await outcome in group {
                    switch outcome {
                    case .timeout:
                        if !allPluginsCompleted { timedOut = true; group.cancelAll() }
                    case .success:
                        successCount += 1; pluginsDone += 1
                    case .failure:
                        failureCount += 1; pluginsDone += 1
                    }
                    if !allPluginsCompleted && pluginsDone == activePlugins.count {
                        allPluginsCompleted = true
                        group.cancelAll()
                    }
                }
            }

            do {
                if let scan = try await Scan.find(scanID, on: db) {
                    if timedOut {
                        app.logger.warning("Scan \(scanID) exceeded 120-second deadline; marking failed")
                        scan.status = .failed
                    } else {
                        // Mark failed only when every plugin threw — partial success is still completed.
                        scan.status = (successCount == 0 && failureCount > 0) ? .failed : .completed
                    }
                    scan.completedAt = Date()
                    try await scan.save(on: db)
                }
            } catch {
                app.logger.error("Failed to mark scan \(scanID) as finished: \(error)")
            }
        }

        return ScanResponse(scanID: scanID, input: input, status: newScan.status.rawValue, results: [])
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
