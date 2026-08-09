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
private let activeSSEConnections = NIOLockedValueBox<Int>(0)
private let maxSSEConnections = 30

struct ScanController: RouteCollection {
    static let defaultPlugins: [any FootprintPlugin] = [
        GravatarPlugin(),
        HaveIBeenPwnedPlugin(),
        EmailIntelPlugin(),
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
        MailSecurityPlugin(),
        WebPosturePlugin(),
        ExposedFilesPlugin(),
        SiteMetaPlugin(),
        BulkUsernamePlugin(),
        BulkEmailPlugin(),
        CrtShPlugin(),
        AttackSurfacePlugin(),
        TyposquatPlugin(),
        WhoisPlugin(),
        WaybackPlugin(),
        ShodanPlugin(),
        InternetDBPlugin(),
        VirusTotalPlugin(),
        AbuseIPDBPlugin(),
        PassiveDNSPlugin()
    ]
    /// Recurring work runs without the high-fan-out plugins. Monitoring remains
    /// useful while avoiding hundreds of outbound requests per target per cycle.
    static let backgroundPlugins: [any FootprintPlugin] = defaultPlugins.filter { !$0.heavy }
    let plugins: [any FootprintPlugin] = ScanController.defaultPlugins

    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        // Two stacked windows: a per-minute burst cap and an hourly sustained cap.
        // The hourly window is far stricter for anonymous callers (15/h vs 200/h)
        // so logged-out users can scan but can't hammer the box. Cloudflare fronts
        // bot/DDoS filtering ahead of this.
        noCache.grouped(ScanRateLimiter(anonMax: 15, authedMax: 200, windowSeconds: 3600))
               .grouped(ScanRateLimiter())
               .post("scan", use: scan)
        noCache.grouped(ScanRateLimiter(anonMax: 60, authedMax: 120, windowSeconds: 60)).get("results", ":id", use: getResults)
        noCache.grouped(ScanRateLimiter(anonMax: 60, authedMax: 120, windowSeconds: 60)).get("stream", ":id", use: streamResults)
        noCache.get("plugins", use: listPlugins)
    }

    @Sendable
    func listPlugins(req: Request) async throws -> [PluginInfo] {
        // Description now lives on each plugin (FootprintPlugin.description). The
        // old central switch keyed off `.name`, but most names had drifted from
        // its cases, so ~17 of 24 plugins silently fell back to "OSINT plugin".
        return self.plugins.map { PluginInfo(name: $0.name, description: $0.description) }
    }

    @Sendable
    func scan(req: Request) async throws -> ScanResponse {
        let scanReq = try req.content.decode(ScanRequest.self)
        let input = try InputValidator.validateScanInput(scanReq.input)

        // Audit log: record every scan request with client IP for later review.
        let clientIP = req.clientIP

        // Logs are operational telemetry, not a second datastore for OSINT
        // targets or precise client addresses. Keep only a coarse target kind
        // and the same /24 or /48 network prefix used by the audit trail.
        let targetKind = input.contains("@") ? "email" : "non_email"
        req.logger.info("Scan requested: target_type=\(targetKind) ip_prefix=\(IPPrivacy.anonymize(clientIP))")

        let requestedPlugins = scanReq.plugins?.map { $0.lowercased() } ?? []
        // A plugin-specific scan is not interchangeable with an earlier default
        // scan, so never reuse/dedupe it solely by target.
        let forceScan = scanReq.force == true || !requestedPlugins.isEmpty
        // A scan older than 7 days is considered stale; a fresh scan will be started.
        let staleThreshold = Date().addingTimeInterval(-7 * 24 * 3600)

        // Resolve the caller up front: dedup and reuse must be scoped to the
        // requester's own scans (or, for anonymous callers, to other anonymous
        // scans). Returning another user's scan — including its results inline —
        // is a cross-tenant leak; the ownership checks in getResults/stream are
        // bypassed entirely by serving a foreign scan from this POST.
        let currentUser = try await req.currentUser()
        let userID = currentUser?.id

        // Heavy plugins are reserved for verified accounts. Anonymous visitors
        // and freshly-created throwaway accounts still get the light OSINT set,
        // but cannot turn one request into hundreds of third-party fetches.
        let eligiblePlugins = currentUser?.emailVerified == true
            ? self.plugins
            : self.plugins.filter { !$0.heavy }
        let activePlugins: [any FootprintPlugin]
        if requestedPlugins.isEmpty {
            activePlugins = eligiblePlugins
        } else {
            activePlugins = eligiblePlugins.filter { requestedPlugins.contains($0.name.lowercased()) }
            guard !activePlugins.isEmpty else {
                throw Abort(.badRequest, reason: "No eligible plugins specified. Heavy plugins require a verified account.")
            }
        }

        // Dedupe: if an *in-flight* pending scan already exists for this input AND
        // this owner, return it so we don't spin up redundant plugin tasks. But a
        // pending scan whose runner died mid-flight (e.g. a process crash) would stay
        // pending forever and block every future scan of that input — so only reuse
        // one young enough to plausibly still be running (the runner deadline is
        // ~120s), and reap an older orphan to `.failed` before starting fresh.
        if requestedPlugins.isEmpty {
            let inFlightCutoff = Date().addingTimeInterval(-180)
            var pendingQuery = Scan.query(on: req.db)
                .filterInput(input)
                .filter(\.$statusRaw == ScanStatus.pending.rawValue)
            if let userID {
                pendingQuery = pendingQuery.filter(\.$user.$id == userID)
            } else {
                pendingQuery = pendingQuery.filter(\.$user.$id == nil)
            }
            if let pendingScan = try await pendingQuery.sort(\.$createdAt, .descending).first() {
                if let createdAt = pendingScan.createdAt, createdAt > inFlightCutoff {
                    return ScanResponse(
                        scanID: pendingScan.id!,
                        input: pendingScan.input,
                        status: pendingScan.status.rawValue,
                        results: [],
                        completedAt: nil,
                        scannedAt: pendingScan.createdAt.map { $0.timeIntervalSince1970 }
                    )
                }
                // Orphaned: the runner is gone. Reap so it stops blocking this input and
                // stops surfacing as a perpetually-pending scan, then fall through to start fresh.
                pendingScan.status = .failed
                try? await pendingScan.save(on: req.db)
            }
        }

        // Reuse a recent completed scan of the SAME owner unless force=true or stale.
        if !forceScan {
            var reuseQuery = Scan.query(on: req.db)
                .filterInput(input)
                .filter(\.$statusRaw != ScanStatus.failed.rawValue)
            if let userID {
                reuseQuery = reuseQuery.filter(\.$user.$id == userID)
            } else {
                reuseQuery = reuseQuery.filter(\.$user.$id == nil)
            }
            if let existingScan = try await reuseQuery
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
        }

        let normalized = input
        let newScan = Scan(input: normalized, userID: userID)
        try await newScan.save(on: req.db)
        await AuditLogger.log(req: req, action: "scan_start", target: String(normalized.prefix(100)))
        guard let scanID = newScan.id else {
            throw Abort(.internalServerError)
        }

        let app = req.application

        await ScanProgressTracker.shared.start(scanID: scanID, total: activePlugins.count)

        // Run plugins in the background so the HTTP request returns immediately.
        // Transitive pivot is the expensive multiplier, so it's account-only:
        // authenticated scans get 2 rounds, anonymous scans get none.
        let pivotDepth = currentUser?.emailVerified == true ? 2 : 0
        Task {
            await ScanPluginRunner.run(scanID: scanID, input: input, plugins: activePlugins, app: app, pivotDepth: pivotDepth)
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

        // Owned scans are owner-only; anonymous scans are readable by anyone
        // holding the unguessable scanID (capability access). See Scan.authorizeRead.
        try await scan.authorizeRead(req)

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
        guard let scan = try await Scan.find(scanID, on: req.db) else {
            throw Abort(.notFound, reason: "Scan not found.")
        }
        // Owned scans are owner-only; anonymous scans are readable by anyone
        // holding the unguessable scanID (capability access).
        try await scan.authorizeRead(req)

        // Enforce a global cap on concurrent SSE connections to protect the DB pool.
        let current = activeSSEConnections.withLockedValue { $0 += 1; return $0 }
        guard current <= maxSSEConnections else {
            activeSSEConnections.withLockedValue { $0 -= 1 }
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
            defer { activeSSEConnections.withLockedValue { $0 -= 1 } }
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
