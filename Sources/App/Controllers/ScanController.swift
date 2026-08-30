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

/// Process-wide counter of active SSE connections. Prevents a burst of open streams
/// from exhausting the PostgreSQL connection pool (default max: 100 connections).
private let activeSSEConnections = NIOLockedValueBox<Int>(0)
private let maxSSEConnections = 30

private struct SSEProgressPayload: Encodable {
    let done: Int
    let total: Int
    let lastPlugin: String
}

private struct SSEDonePayload: Encodable {
    let status: String
    let count: Int
    let riskScore: Int
    let riskLevel: String
}

private struct SSEErrorPayload: Encodable {
    let code: String
}

private func sseFrame<T: Encodable>(event: String, payload: T, id: Int64? = nil) throws -> ByteBuffer {
    let encoded = try JSONEncoder().encode(payload)
    let json = String(decoding: encoded, as: UTF8.self)
    let idLine = id.map { "id: \($0)\n" } ?? ""
    return ByteBuffer(string: "\(idLine)event: \(event)\ndata: \(json)\n\n")
}

/// Accept only canonical non-negative decimal cursors. Besides bounding parser
/// work, rejecting signs/whitespace avoids multiple textual representations of
/// the same stream position in logs and intermediaries.
private func requestedSSECursor(_ req: Request) throws -> Int64 {
    let queryCursor: String? = try? req.query.get(String.self, at: "cursor")
    guard let raw = req.headers.first(name: "Last-Event-ID") ?? queryCursor else {
        return 0
    }
    let bytes = Array(raw.utf8)
    guard (1...19).contains(bytes.count),
          bytes.allSatisfy({ (48...57).contains($0) }),
          let cursor = Int64(raw), cursor >= 0 else {
        throw Abort(.badRequest, reason: "Invalid SSE cursor.")
    }
    return cursor
}

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
                        input: try pendingScan.input,
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
                    input: try existingScan.input,
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

        // Count only the plugins that can act on this input's shape, so the bar
        // tracks real work instead of jumping as the irrelevant ones no-op.
        let runnablePlugins = ScanPluginRunner.applicablePlugins(activePlugins, for: input)
        await ScanProgressTracker.shared.start(scanID: scanID, total: runnablePlugins.count)

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
            input: try scan.input,
            status: scan.status.rawValue,
            results: scan.results,
            completedAt: scan.completedAt.map { $0.timeIntervalSince1970 },
            scannedAt: scan.createdAt.map { $0.timeIntervalSince1970 }
        )
    }

    // SSE stream: replays durable, per-scan result events after Last-Event-ID and
    // then tails new events. The 90-second response window remains below the
    // proxy origin timeout; EventSource reconnects with its last acknowledged ID.
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

        let initialCursor = try requestedSSECursor(req)
        guard try await ResultStreamStore.contains(
            scanID: scanID,
            cursor: initialCursor,
            on: req.db
        ) else {
            throw Abort(.badRequest, reason: "SSE cursor is outside this scan's retained history.")
        }

        // Enforce a global cap on concurrent SSE connections to protect the DB pool.
        let current = activeSSEConnections.withLockedValue { $0 += 1; return $0 }
        guard current <= maxSSEConnections else {
            activeSSEConnections.withLockedValue { $0 -= 1 }
            throw Abort(.serviceUnavailable, reason: "Too many active streams; please retry shortly.")
        }

        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "text/event-stream")
        headers.add(name: "Cache-Control", value: "no-store, no-cache, must-revalidate")
        // Tell nginx (and Cloudflare) not to buffer the SSE stream.
        headers.add(name: "X-Accel-Buffering", value: "no")

        let db = req.db
        let logger = req.logger
        let application = req.application

        let body = Response.Body(managedAsyncStream: { writer in
            defer { activeSSEConnections.withLockedValue { $0 -= 1 } }
            var cursor = initialCursor
            var lastProgress: (done: Int, total: Int, lastPlugin: String)?
            var heartbeatTick = 0
            let deadline = Date().addingTimeInterval(90)

            // Browser reconnect delay. EventSource retains the last `id:` value
            // and sends it back as Last-Event-ID on the next connection.
            try await writer.writeBuffer(ByteBuffer(string: "retry: 2000\n\n"))

            do {
                while Date() < deadline {
                    guard let currentScan = try await Scan.find(scanID, on: db) else {
                        try await writer.writeBuffer(try sseFrame(
                            event: "stream-error",
                            payload: SSEErrorPayload(code: "scan_unavailable")
                        ))
                        return
                    }

                    let events = try await ResultStreamStore.replay(
                        scanID: scanID,
                        after: cursor,
                        on: db
                    )
                    for streamEvent in events {
                        let result = streamEvent.result
                        let payload = PluginResult(
                            source: result.source,
                            type: result.type,
                            confidenceScore: result.confidenceScore,
                            rawData: try result.rawData,
                            metadata: try result.metadataObject
                        )
                        try await writer.writeBuffer(try sseFrame(
                            event: "result",
                            payload: payload,
                            id: streamEvent.streamSequence
                        ))
                        cursor = streamEvent.streamSequence
                    }

                    // Drain a full replay page immediately. Only wait once the
                    // stream has caught up, keeping large reconnects fast while
                    // bounding every individual database query.
                    if events.count == ResultStreamStore.replayLimit {
                        continue
                    }

                    if currentScan.status == .completed || currentScan.status == .failed {
                        let allResults = try await Result.query(on: db)
                            .filter(\.$scan.$id == scanID)
                            .all()
                        let risk = try RiskScorer.compute(results: allResults)
                        try await writer.writeBuffer(try sseFrame(
                            event: "done",
                            payload: SSEDonePayload(
                                status: currentScan.status.rawValue,
                                count: allResults.count,
                                riskScore: risk.value,
                                riskLevel: risk.level.rawValue
                            )
                        ))
                        return
                    }

                    if let progress = await ScanProgressTracker.shared.get(for: scanID),
                       lastProgress?.done != progress.done
                            || lastProgress?.total != progress.total
                            || lastProgress?.lastPlugin != progress.lastName {
                        let payload = SSEProgressPayload(
                            done: progress.done,
                            total: progress.total,
                            lastPlugin: progress.lastName
                        )
                        try await writer.writeBuffer(try sseFrame(event: "progress", payload: payload))
                        lastProgress = (progress.done, progress.total, progress.lastName)
                    }

                    heartbeatTick += 1
                    if heartbeatTick >= 15 {
                        try await writer.writeBuffer(ByteBuffer(string: ": heartbeat\n\n"))
                        heartbeatTick = 0
                    }
                    try await Task.sleep(for: .seconds(1))
                }

                // End this HTTP response before the proxy timeout without
                // claiming the scan itself timed out. EventSource reconnects
                // and resumes from the last durable result ID.
                logger.debug("SSE stream for scan \(scanID) reached its reconnect boundary.")
                try await writer.writeBuffer(ByteBuffer(string: ": reconnect\n\n"))
            } catch let failure as FieldCrypto.DecryptionFailure {
                await SensitiveFieldFailureReporter.report(
                    failure,
                    app: application,
                    context: "scan_stream"
                )
                try await writer.writeBuffer(try sseFrame(
                    event: "stream-error",
                    payload: SSEErrorPayload(code: "stored_data_unavailable")
                ))
            }
        })

        return Response(status: .ok, headers: headers, body: body)
    }
}
