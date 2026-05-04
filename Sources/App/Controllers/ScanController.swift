import Vapor
import Fluent
import NIOConcurrencyHelpers
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct ScanRequest: Content {
    let input: String
    let force: Bool?
    let plugins: [String]?  // if nil/empty → run all plugins
}

struct PluginInfo: Content {
    let name: String
    let description: String
}

struct ScanResponse: Content {
    let scanID: UUID
    let input: String
    let status: String
    let results: [Result]
    let completedAt: Double?  // Unix timestamp (seconds since 1970), nil if not yet finished
    let scannedAt: Double?    // Unix timestamp of scan creation
}

/// Global counter of active SSE connections. Prevents a burst of open streams
/// from exhausting the PostgreSQL connection pool (default max: 100 connections).
private let activeSSEConnections = NIOAtomic<Int>.makeAtomic(value: 0)
private let maxSSEConnections = 30

struct ScanController: RouteCollection {
    static let defaultPlugins: [any FootprintPlugin] = [
        GravatarPlugin(),
        HaveIBeenPwnedPlugin(),
        UsernamePlugin(),
        GitLabPlugin(),
        RedditPlugin(),
        TwitterPlugin(),
        KeybasePlugin(),
        TelegramPlugin(),
        MastodonPlugin(),
        HackerNewsPlugin(),
        SteamPlugin(),
        NpmPlugin(),
        PyPIPlugin(),
        PastebinPlugin(),
        PhonePlugin(),
        DomainPlugin(),
        BulkUsernamePlugin(),
        BulkEmailPlugin(),
        CrtShPlugin(),
        WhoisPlugin(),
        ShodanPlugin(),
        VirusTotalPlugin(),
        AbuseIPDBPlugin(),
        PassiveDNSPlugin()
    ]
    let plugins: [any FootprintPlugin] = ScanController.defaultPlugins

    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.grouped(ScanRateLimiter()).post("scan", use: scan)
        noCache.grouped(ScanRateLimiter(anonMax: 60, authedMax: 120, windowSeconds: 60)).get("results", ":id", use: getResults)
        noCache.grouped(ScanRateLimiter(anonMax: 60, authedMax: 120, windowSeconds: 60)).get("stream", ":id", use: streamResults)
        noCache.get("plugins", use: listPlugins)
    }

    @Sendable
    func listPlugins(req: Request) async throws -> [PluginInfo] {
        return self.plugins.map { PluginInfo(name: $0.name, description: descriptionFor($0.name)) }
    }

    private func descriptionFor(_ name: String) -> String {
        switch name {
        case "Gravatar": return "Profile picture lookup by email"
        case "HaveIBeenPwned": return "Email breach database check"
        case "Username": return "Username presence on 50+ platforms"
        case "GitLab": return "GitLab profile search"
        case "Reddit": return "Reddit account lookup"
        case "Twitter": return "Twitter/X profile search"
        case "Keybase": return "Keybase identity lookup"
        case "Telegram": return "Telegram username search"
        case "Mastodon": return "Mastodon account search"
        case "HackerNews": return "Hacker News profile lookup"
        case "Steam": return "Steam profile search"
        case "Npm": return "NPM package author lookup"
        case "PyPI": return "PyPI package author lookup"
        case "Pastebin": return "Pastebin content search"
        case "Phone": return "Phone number OSINT"
        case "DomainOSINT": return "DNS records, WHOIS, SSL info"
        case "BulkUsername": return "Sherlock: 480+ platform username check"
        case "BulkEmail": return "Holehe: email-to-account correlation"
        case "CrtSh": return "Certificate Transparency subdomain enumeration"
        case "Whois": return "RDAP domain registration info"
        case "Shodan": return "Exposed ports and services (requires API key)"
        case "VirusTotal": return "Malware/reputation check for domains and IPs (requires API key)"
        case "AbuseIPDB": return "IP abuse reputation score (requires API key)"
        case "PassiveDNS": return "Historical DNS and subdomain discovery"
        default: return "OSINT plugin"
        }
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

        let userID = try await req.currentUser()?.id

        let normalized = input
        let newScan = Scan(input: normalized, userID: userID)
        try await newScan.save(on: req.db)
        AuditLogger.log(req: req, action: "scan_start", target: String(normalized.prefix(100)))
        guard let scanID = newScan.id else {
            throw Abort(.internalServerError)
        }

        let app = req.application

        // E2: Filter plugins based on request
        let requestedPlugins = scanReq.plugins?.map { $0.lowercased() } ?? []
        let activePlugins: [any FootprintPlugin]
        if requestedPlugins.isEmpty {
            activePlugins = self.plugins
        } else {
            activePlugins = self.plugins.filter { requestedPlugins.contains($0.name.lowercased()) }
            guard !activePlugins.isEmpty else {
                throw Abort(.badRequest, reason: "No valid plugins specified")
            }
        }

        await ScanProgressTracker.shared.start(scanID: scanID, total: activePlugins.count)

        // Run plugins in the background so the HTTP request returns immediately.
        Task {
            await ScanController.runPlugins(scanID: scanID, input: input, plugins: activePlugins, app: app)
        }

        return ScanResponse(scanID: scanID, input: input, status: newScan.status.rawValue, results: [], completedAt: nil, scannedAt: newScan.createdAt.map { $0.timeIntervalSince1970 })
    }

    /// Shared plugin runner — called from both scan() and BulkScanController.
    /// The caller is responsible for starting ScanProgressTracker before the Task.
    static func runPlugins(scanID: UUID, input: String, plugins: [any FootprintPlugin], app: Application) async {
        // In the test environment there are no external services to reach,
        // and the background URLSession calls generate SIGPIPE when the app
        // shuts down immediately after the test.  Skip execution entirely.
        guard app.environment != .testing else { return }

        guard let db = app.databases.database(
            nil, logger: app.logger, on: app.eventLoopGroup.any()
        ) else {
            app.logger.warning("Scan \(scanID): database unavailable, skipping plugin execution")
            return
        }

        var successCount = 0
        var failureCount = 0
        var timedOut = false

        enum PluginOutcome {
            case success(pluginName: String)
            case failure(pluginName: String)
            case timeout
        }

        await withTaskGroup(of: PluginOutcome.self) { group in
            // Timeout sentinel: cancels all plugins if 120 s elapse.
            group.addTask {
                try? await Task.sleep(for: .seconds(120))
                return .timeout
            }

            for plugin in plugins {
                let pName = plugin.name
                group.addTask {
                    guard !Task.isCancelled else { return .failure(pluginName: pName) }
                    do {
                        let pluginResults = try await plugin.scan(input: input, on: app)
                        for pr in pluginResults {
                            let cappedRawData = pr.rawData.count > 8192
                                ? String(pr.rawData.prefix(8192)) + "… [truncated]"
                                : pr.rawData
                            let result = Result(
                                scanID: scanID,
                                source: String(pr.source.prefix(64)),
                                type: String(pr.type.prefix(64)),
                                confidenceScore: max(0.0, min(1.0, pr.confidenceScore)),
                                rawData: cappedRawData
                            )
                            try await result.save(on: db)
                        }
                        return .success(pluginName: pName)
                    } catch {
                        app.logger.error("Plugin \(pName) failed: \(error)")
                        return .failure(pluginName: pName)
                    }
                }
            }

            var pluginsDone = 0
            var allPluginsCompleted = false
            for await outcome in group {
                switch outcome {
                case .timeout:
                    if !allPluginsCompleted { timedOut = true; group.cancelAll() }
                case .success(let name):
                    successCount += 1; pluginsDone += 1
                    await ScanProgressTracker.shared.complete(scanID: scanID, pluginName: name)
                case .failure(let name):
                    failureCount += 1; pluginsDone += 1
                    await ScanProgressTracker.shared.complete(scanID: scanID, pluginName: name)
                }
                if !allPluginsCompleted && pluginsDone == plugins.count {
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
                    scan.status = (successCount == 0 && failureCount > 0) ? .failed : .completed
                }
                scan.completedAt = Date()
                try await scan.save(on: db)
                await ScanProgressTracker.shared.remove(for: scanID)
                // Fire webhook if user has one set.
                if let userID = scan.$user.id,
                   let user = try? await User.find(userID, on: db),
                   let hookURL = user.webhookURL {
                    let allResults = try await App.Result.query(on: db).filter(\.$scan.$id == scanID).all()
                    let risk = RiskScorer.compute(results: allResults)
                    await fireWebhook(url: hookURL, scanID: scanID, scan: scan, risk: risk, resultCount: allResults.count, logger: app.logger)
                }
            }
        } catch {
            app.logger.error("Failed to mark scan \(scanID) as finished: \(error)")
        }
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

        // Enforce a global cap on concurrent SSE connections to protect the DB pool.
        let current = activeSSEConnections.add(1)
        guard current <= maxSSEConnections else {
            activeSSEConnections.sub(1)
            throw Abort(.serviceUnavailable, reason: "Too many active streams; please retry shortly.")
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
            defer { activeSSEConnections.sub(1) }
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
                        try await writer.writeBuffer(ByteBuffer(string: "event: result\ndata: \(json)\n\n"))
                    }
                }
                lastCount = results.count

                if scan.status == .completed || scan.status == .failed {
                    let risk = RiskScorer.compute(results: results)
                    let payload = "{\"status\":\"\(scan.status.rawValue)\",\"count\":\(results.count),\"riskScore\":\(risk.value),\"riskLevel\":\"\(risk.level.rawValue)\"}"
                    try await writer.writeBuffer(ByteBuffer(string: "event: done\ndata: \(payload)\n\n"))
                    return
                }

                // Emit progress event
                if let prog = await ScanProgressTracker.shared.get(for: scanID) {
                    let escaped = prog.lastName.replacingOccurrences(of: "\\", with: "\\\\")
                                               .replacingOccurrences(of: "\"", with: "\\\"")
                    let progressPayload = "{\"done\":\(prog.done),\"total\":\(prog.total),\"lastPlugin\":\"\(escaped)\"}"
                    try await writer.writeBuffer(ByteBuffer(string: "event: progress\ndata: \(progressPayload)\n\n"))
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

private func fireWebhook(url: String, scanID: UUID, scan: Scan, risk: RiskScorer.Score, resultCount: Int, logger: Logger) async {
    guard let hookURL = URL(string: url) else { return }
    let payload: [String: Any] = [
        "event": "scan.completed",
        "scanID": scanID.uuidString,
        "input": scan.input,
        "status": scan.status.rawValue,
        "riskScore": risk.value,
        "riskLevel": risk.level.rawValue,
        "resultCount": resultCount,
        "completedAt": scan.completedAt.map { $0.timeIntervalSince1970 } as Any
    ]
    guard let body = try? JSONSerialization.data(withJSONObject: payload) else { return }
    var request = URLRequest(url: hookURL)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = body
    request.timeoutInterval = 10
    do {
        _ = try await URLSession.shared.data(for: request)
    } catch {
        logger.warning("Webhook delivery to \(url) failed: \(error)")
    }
}
