import Vapor
import Fluent

struct ScanRequest: Content {
    let input: String
    let force: Bool?
}

struct ScanResponse: Content {
    let scanID: UUID
    let input: String
    let status: String
    let results: [Result]
    let completedAt: Double?  // Unix timestamp (seconds since 1970), nil if not yet finished
    let scannedAt: Double?    // Unix timestamp of scan creation
}

struct ScanController: RouteCollection {
    let plugins: [any FootprintPlugin] = [
        GravatarPlugin(),
        HaveIBeenPwnedPlugin(),
        UsernamePlugin(),
        RedditPlugin(),
        PhonePlugin(),
        BulkUsernamePlugin(),
        BulkEmailPlugin()
    ]

    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.grouped(ScanRateLimiter()).post("scan", use: scan)
        noCache.grouped(ScanRateLimiter(maxRequests: 60, windowSeconds: 60)).get("results", ":id", use: getResults)
        noCache.grouped(ScanRateLimiter(maxRequests: 60, windowSeconds: 60)).get("stream", ":id", use: streamResults)
    }

    @Sendable
    func scan(req: Request) async throws -> ScanResponse {
        let scanReq = try req.content.decode(ScanRequest.self)

        // Trim whitespace and normalise emails to lowercase so "User@Example.com"
        // reuses the same cache entry as "user@example.com".
        let trimmed = scanReq.input.trimmingCharacters(in: .whitespacesAndNewlines)
        let input   = trimmed.contains("@") ? trimmed.lowercased() : trimmed
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

        // Mask PII in logs: show only domain part for emails, first 3 chars for usernames.
        let logSafe: String
        if let atIdx = input.firstIndex(of: "@") {
            logSafe = "***@" + String(input[input.index(after: atIdx)...])
        } else {
            logSafe = String(input.prefix(3)) + "***"
        }
        req.logger.info("Scan requested: input=\(logSafe) ip=\(clientIP)")

        let forceScan = scanReq.force == true
        // A scan older than 7 days is considered stale; a fresh scan will be started.
        let staleThreshold = Date().addingTimeInterval(-7 * 24 * 3600)

        // Dedupe: if a pending scan already exists for this input, return it immediately
        // so we don't spin up redundant parallel plugin tasks.
        if let pendingScan = try await Scan.query(on: req.db)
            .filter(\.$input == input)
            .filter(\.$statusRaw == ScanStatus.pending.rawValue)
            .first() {
            return ScanResponse(
                scanID: pendingScan.id!,
                input: pendingScan.input,
                status: pendingScan.status.rawValue,
                results: [],
                completedAt: nil,
                scannedAt: pendingScan.createdAt.map { $0.timeIntervalSince1970 }
            )
        }

        // Reuse a recent completed scan unless force=true or the data is stale.
        if !forceScan,
           let existingScan = try await Scan.query(on: req.db)
               .filter(\.$input == input)
               .filter(\.$statusRaw != ScanStatus.failed.rawValue)
               .with(\.$results)
               .sort(\.$createdAt, .descending)
               .first(),
           let createdAt = existingScan.createdAt,
           createdAt > staleThreshold {
            return ScanResponse(
                scanID: existingScan.id!,
                input: existingScan.input,
                status: existingScan.status.rawValue,
                results: existingScan.results,
                completedAt: existingScan.completedAt.map { $0.timeIntervalSince1970 },
                scannedAt: existingScan.createdAt.map { $0.timeIntervalSince1970 }
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

        return ScanResponse(scanID: scanID, input: input, status: newScan.status.rawValue, results: [], completedAt: nil, scannedAt: newScan.createdAt.map { $0.timeIntervalSince1970 })
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
            results: scan.results,
            completedAt: scan.completedAt.map { $0.timeIntervalSince1970 },
            scannedAt: scan.createdAt.map { $0.timeIntervalSince1970 }
        )
    }

    // SSE stream: pushes each plugin result to the client as it is saved to the DB.
    // Polls the database every second for up to 90 seconds (safely under Cloudflare's
    // 100-second origin-read timeout). Sends "event: done" when the scan reaches a
    // terminal state or the deadline expires; the client should then fall back to
    // a final GET /results/:id for export/history metadata.
    @Sendable
    func streamResults(req: Request) async throws -> Response {
        guard let idString = req.parameters.get("id"), let scanID = UUID(uuidString: idString) else {
            throw Abort(.badRequest, reason: "Invalid scan ID format.")
        }
        guard try await Scan.find(scanID, on: req.db) != nil else {
            throw Abort(.notFound, reason: "Scan not found.")
        }

        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "text/event-stream")
        headers.add(name: "Cache-Control", value: "no-cache")
        // Tell nginx (and Cloudflare) not to buffer the SSE stream.
        headers.add(name: "X-Accel-Buffering", value: "no")

        let db = req.db
        let logger = req.logger
        let encoder = JSONEncoder()

        let body = Response.Body(managedAsyncStream: { writer in
            var lastCount = 0

            for _ in 0..<90 {
                guard let scan = try? await Scan.find(scanID, on: db) else { break }

                let results = (try? await Result.query(on: db)
                    .filter(\Result.$scan.$id == scanID)
                    .all()) ?? []

                // Stream any results added since the last poll.
                for result in results.dropFirst(lastCount) {
                    let pr = PluginResult(
                        source: result.source,
                        type: result.type,
                        confidenceScore: result.confidenceScore,
                        rawData: result.rawData
                    )
                    if let data = try? encoder.encode(pr),
                       let json = String(data: data, encoding: .utf8) {
                        try await writer.writeBuffer(ByteBuffer(string: "data: \(json)\n\n"))
                    }
                }
                lastCount = results.count

                if scan.status == .completed || scan.status == .failed {
                    let payload = "{\"status\":\"\(scan.status.rawValue)\",\"count\":\(results.count)}"
                    try await writer.writeBuffer(ByteBuffer(string: "event: done\ndata: \(payload)\n\n"))
                    return
                }

                // Keepalive comment — resets Cloudflare's 100-second origin timeout.
                try await writer.writeBuffer(ByteBuffer(string: ": ka\n\n"))
                try await Task.sleep(nanoseconds: 1_000_000_000)
            }

            // Deadline exceeded.
            logger.warning("SSE stream for scan \(scanID) exceeded 90-second deadline.")
            try await writer.writeBuffer(ByteBuffer(string: "event: done\ndata: {\"status\":\"timeout\",\"count\":0}\n\n"))
        })

        return Response(status: .ok, headers: headers, body: body)
    }
}
