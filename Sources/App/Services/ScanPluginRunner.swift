import Vapor
import Fluent
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Executes a set of OSINT plugins for a given scan: runs them concurrently in a
/// `TaskGroup` with a hard 120-second deadline, persists each result to the DB
/// as it arrives, drives `ScanProgressTracker`, marks the parent `Scan` row as
/// `.completed` / `.failed`, and fires the user's webhook on completion.
///
/// Shared by `ScanController.scan` and `BulkScanController.bulkScan`. The caller
/// is responsible for starting `ScanProgressTracker` before invoking `run`.
enum ScanPluginRunner {

    /// - Parameter useCache: when true (default), each plugin's output is
    ///   served from `PluginCacheStore` if a non-expired entry exists for
    ///   `(plugin.name, sha256(input))`, and fresh runs are written back.
    ///   Scheduled scans pass `false` because monitor mode is specifically
    ///   about detecting *new* findings — a cache hit would mask them.
    /// - Parameter pivotDepth: how many transitive pivot rounds to run after the
    ///   main round (default 1). Authenticated interactive scans pass 2 for a
    ///   deeper chain; anonymous and scheduled scans keep 1 to bound cost.
    static func run(scanID: UUID, input: String, plugins: [any FootprintPlugin], app: Application, useCache: Bool = true, pivotDepth: Int = 1) async {
        // In the test environment there are no external services to reach, and
        // background HTTP calls can race app shutdown. Skip execution entirely.
        guard app.environment != .testing else { return }

        guard await ScanExecutionGate.shared.acquire() else {
            app.logger.warning("Scan \(scanID) rejected: execution queue is full")
            if let scan = try? await Scan.find(scanID, on: app.db) {
                scan.status = .failed
                scan.completedAt = Date()
                try? await scan.save(on: app.db)
            }
            await ScanProgressTracker.shared.remove(for: scanID)
            return
        }
        defer {
            Task { await ScanExecutionGate.shared.release() }
        }

        guard let db = app.databases.database(
            nil, logger: app.logger, on: app.eventLoopGroup.any()
        ) else {
            app.logger.warning("Scan \(scanID): database unavailable, skipping plugin execution")
            return
        }

        // Round 1: full plugin set on the input and its derived candidates
        // (e.g. an email yields its local-part as a username so username-gated
        // plugins are reached). See TargetDeriver.
        let candidates = TargetDeriver.candidates(for: input)
        let round1 = await runRound(
            plugins: plugins, candidates: candidates, scanID: scanID,
            deadline: 120, expectedUnits: plugins.count, reportProgress: true,
            app: app, db: db, useCache: useCache
        )

        // Transitive pivot rounds: re-scan identifiers discovered in the previous
        // round (commit emails, linked handles, …) with the LIGHT plugins only
        // (the 480-site sweep is excluded to stay fast). Each round mines only the
        // *new* results and a small candidate cap, so the chain can't explode;
        // `pivotDepth` rounds run at most.
        var alreadyScanned = Set(candidates.map { $0.value.lowercased() })
        var frontier = round1.collected
        let lightPlugins = plugins.filter { !$0.heavy }
        var pivotSuccess = 0
        var levelsLeft = max(0, pivotDepth)
        while levelsLeft > 0 {
            let pivots = PivotExtractor.candidates(from: frontier, alreadyScanned: alreadyScanned)
            guard !pivots.isEmpty else { break }
            alreadyScanned.formUnion(pivots)
            let pivotCandidates = pivots.map { TargetDeriver.Candidate(value: $0, origin: .pivoted) }
            let round = await runRound(
                plugins: lightPlugins, candidates: pivotCandidates, scanID: scanID,
                deadline: 45, expectedUnits: lightPlugins.count, reportProgress: false,
                app: app, db: db, useCache: useCache
            )
            pivotSuccess += round.success
            frontier = round.collected
            levelsLeft -= 1
            app.logger.info("Scan \(scanID): pivot round scanned \(pivots.count) discovered entit(ies); \(levelsLeft) level(s) left")
        }

        let successCount = round1.success + pivotSuccess
        let timedOut = round1.timedOut

        do {
            if let scan = try await Scan.find(scanID, on: db) {
                // A scan is "completed" as soon as ANY plugin returned (even a
                // timed-out scan keeps the results plugins already produced — they
                // were persisted as they arrived). Only mark "failed" when nothing
                // succeeded: every plugin errored, or the deadline hit before any
                // finished. This stops a single slow plugin from burying real,
                // already-saved findings under a "failed" badge.
                if successCount > 0 {
                    if timedOut {
                        app.logger.warning("Scan \(scanID) hit the 120-second deadline; completing with \(successCount) partial result set(s)")
                    }
                    scan.status = .completed
                } else {
                    if timedOut {
                        app.logger.warning("Scan \(scanID) exceeded 120-second deadline with no results; marking failed")
                    }
                    scan.status = .failed
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
                    await fireWebhook(url: hookURL, scanID: scanID, scan: scan, risk: risk, resultCount: allResults.count, app: app)
                }
            }
        } catch {
            app.logger.error("Failed to mark scan \(scanID) as finished: \(error)")
        }
    }

    /// Runs `plugins` over `candidates` concurrently under a `deadline`, persists
    /// each result (with its candidate origin), and returns the raw results
    /// (for pivot mining) plus success/failure/timeout aggregates.
    private static func runRound(
        plugins: [any FootprintPlugin],
        candidates: [TargetDeriver.Candidate],
        scanID: UUID,
        deadline: Double,
        expectedUnits: Int,
        reportProgress: Bool,
        app: Application,
        db: Database,
        useCache: Bool
    ) async -> (collected: [PluginResult], success: Int, failure: Int, timedOut: Bool) {

        enum Outcome {
            case done(name: String, succeeded: Bool, results: [PluginResult])
            case timeout
        }

        var collected: [PluginResult] = []
        var success = 0
        var failure = 0
        var timedOut = false

        await withTaskGroup(of: Outcome.self) { group in
            group.addTask {
                try? await Task.sleep(for: .seconds(deadline))
                return .timeout
            }

            for plugin in plugins {
                let pName = plugin.name
                let pTTL = plugin.cacheTTL
                // Heavy plugins (the 480-site sweep) skip non-heavy-eligible
                // candidates so fan-out can't trigger several expensive runs.
                let pCandidates = plugin.heavy ? candidates.filter { $0.origin.heavyEligible } : candidates
                group.addTask {
                    guard !Task.isCancelled else { return .done(name: pName, succeeded: false, results: []) }
                    do {
                        var produced: [PluginResult] = []
                        for candidate in pCandidates {
                            let cInput = candidate.value
                            let raw: [PluginResult]
                            if useCache, let cached = await PluginCacheStore.lookup(pluginName: pName, input: cInput, on: db) {
                                raw = cached
                            } else {
                                let fresh = try await plugin.scan(input: cInput, on: app)
                                if useCache {
                                    await PluginCacheStore.store(pluginName: pName, input: cInput, results: fresh, ttl: pTTL, on: db, logger: app.logger)
                                }
                                raw = fresh
                            }
                            for pr in raw {
                                try await persist(pr, origin: candidate.origin, scanID: scanID, on: db)
                                produced.append(pr)
                            }
                        }
                        return .done(name: pName, succeeded: true, results: produced)
                    } catch {
                        app.logger.error("Plugin \(pName) failed: \(error)")
                        return .done(name: pName, succeeded: false, results: [])
                    }
                }
            }

            var pluginsDone = 0
            var allDone = false
            for await outcome in group {
                switch outcome {
                case .timeout:
                    if !allDone { timedOut = true; group.cancelAll() }
                case .done(let name, let succeeded, let results):
                    if succeeded { success += 1 } else { failure += 1 }
                    pluginsDone += 1
                    collected.append(contentsOf: results)
                    if reportProgress { await ScanProgressTracker.shared.complete(scanID: scanID, pluginName: name) }
                }
                if !allDone && pluginsDone == expectedUnits {
                    allDone = true
                    group.cancelAll()
                }
            }
        }

        return (collected, success, failure, timedOut)
    }

    /// Persists one plugin result. Derived findings (a username inferred from an
    /// email local-part, or a username variant) get a confidence discount and a
    /// provenance note/marker: the account exists, but its link to the original
    /// target is an inference, not a proven fact — the strength of which depends
    /// on the candidate's `origin`.
    private static func persist(_ pr: PluginResult, origin: TargetDeriver.Origin, scanID: UUID, on db: Database) async throws {
        let rawBase = origin.note.map { "\($0) \(pr.rawData)" } ?? pr.rawData
        let cappedRawData = rawBase.count > 8192 ? String(rawBase.prefix(8192)) + "… [truncated]" : rawBase

        var metaDict = pr.metadata ?? [:]
        if origin.derived { metaDict["derivedFrom"] = origin.note ?? "derived" }
        let metadataJSON: String?
        if metaDict.isEmpty {
            metadataJSON = nil
        } else if let data = try? JSONEncoder().encode(metaDict),
                  let json = String(data: data, encoding: .utf8), json.count <= 4096 {
            metadataJSON = json
        } else {
            metadataJSON = nil
        }

        let confidence = max(0.0, min(1.0, pr.confidenceScore)) * origin.confidenceFactor
        let result = Result(
            scanID: scanID,
            source: String(pr.source.prefix(64)),
            type: String(pr.type.prefix(64)),
            confidenceScore: confidence,
            rawData: cappedRawData,
            metadata: metadataJSON
        )
        try await result.save(on: db)
    }

    private static func fireWebhook(url: String, scanID: UUID, scan: Scan, risk: RiskScorer.Score, resultCount: Int, app: Application) async {
        guard let hookURL = URL(string: url) else { return }
        let destination = redactedDestination(hookURL)
        guard !SSRFGuard.isInternalURL(hookURL) else {
            app.logger.warning("Webhook delivery to \(destination) blocked: internal/private target.")
            return
        }
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
        do {
            // SafeHTTP re-checks DNS resolution and blocks redirects to internal
            // hosts, on top of the structural guard above.
            try await SafeHTTP.post(url: hookURL, body: body, on: app)
        } catch SafeHTTP.SafeHTTPError.blockedInternalHost {
            app.logger.warning("Webhook delivery to \(destination) blocked: resolved to an internal address.")
        } catch {
            app.logger.warning("Webhook delivery to \(destination) failed: \(error)")
        }
    }

    /// Never include a webhook's path, query, fragment, or user-info in logs:
    /// those components commonly carry bot tokens and signing secrets.
    private static func redactedDestination(_ url: URL) -> String {
        guard let scheme = url.scheme, let host = url.host else { return "invalid-destination" }
        return "\(scheme.lowercased())://\(host.lowercased())\(url.port.map { ":\($0)" } ?? "")"
    }
}
