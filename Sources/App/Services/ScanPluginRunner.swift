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

        // Deduplicates identical findings across round 1 and every pivot round of
        // this scan — see ResultDedupStore.
        let dedup = ResultDedupStore()

        // Round 1: full plugin set on the input and its derived candidates
        // (e.g. an email yields its local-part as a username so username-gated
        // plugins are reached). See TargetDeriver.
        let candidates = TargetDeriver.candidates(for: input)
        let round1 = await runRound(
            plugins: plugins, candidates: candidates, scanID: scanID,
            deadline: 120, perPluginTimeout: 100, reportProgress: true,
            app: app, db: db, useCache: useCache, dedup: dedup
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
                deadline: 45, perPluginTimeout: 30, reportProgress: false,
                app: app, db: db, useCache: useCache, dedup: dedup
            )
            pivotSuccess += round.success
            frontier = round.collected
            levelsLeft -= 1
            app.logger.info("Scan \(scanID): pivot round scanned \(pivots.count) discovered entit(ies); \(levelsLeft) level(s) left")
        }

        let successCount = round1.success + pivotSuccess
        let timedOut = round1.timedOut
        // Shape gating means a round can legitimately run nothing at all (an
        // input no plugin can act on). That is an empty result, not a failure —
        // unless the deadline is what stopped us before anything finished.
        let ranNothing = round1.success + round1.failure == 0 && !timedOut

        do {
            if let scan = try await Scan.find(scanID, on: db) {
                // A scan is "completed" as soon as ANY plugin returned (even a
                // timed-out scan keeps the results plugins already produced — they
                // were persisted as they arrived). Only mark "failed" when nothing
                // succeeded: every plugin errored, or the deadline hit before any
                // finished. This stops a single slow plugin from burying real,
                // already-saved findings under a "failed" badge.
                if successCount > 0 || ranNothing {
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
                // Persist webhook work before returning. Provider/network
                // failures are retried by the leased outbox worker instead of
                // being silently lost at the end of this background task.
                do {
                    if let userID = scan.$user.id,
                       let user = try? await User.find(userID, on: db),
                       try user.webhookURL != nil {
                        let allResults = try await App.Result.query(on: db)
                            .filter(\.$scan.$id == scanID)
                            .all()
                        let risk = try RiskScorer.compute(results: allResults)
                        let input = try scan.input
                        let webhookPayload: [String: Any] = [
                            "event": "scan.completed",
                            "scanID": scanID.uuidString.lowercased(),
                            "input": input,
                            "status": scan.status.rawValue,
                            "riskScore": risk.value,
                            "riskLevel": risk.level.rawValue,
                            "resultCount": allResults.count,
                            "completedAt": scan.completedAt?.timeIntervalSince1970 ?? NSNull()
                        ]
                        let webhookData = try JSONSerialization.data(
                            withJSONObject: webhookPayload,
                            options: [.sortedKeys]
                        )
                        _ = try await NotificationOutbox.enqueueWebhook(
                            userID: userID,
                            title: "Scan complete",
                            message: "Scan completed with \(allResults.count) result(s); risk \(risk.level.rawValue) (\(risk.value)/100).",
                            webhookBody: String(decoding: webhookData, as: UTF8.self),
                            scanID: scanID,
                            idempotencyKey: "scan-complete-webhook:\(scanID.uuidString.lowercased())",
                            app: app
                        )
                    }
                } catch let failure as FieldCrypto.DecryptionFailure {
                    await SensitiveFieldFailureReporter.report(
                        failure,
                        app: app,
                        context: "scan_completion_webhook"
                    )
                } catch {
                    app.logger.error("Scan \(scanID): completion webhook enqueue failed.")
                }
            }
        } catch let failure as FieldCrypto.DecryptionFailure {
            await SensitiveFieldFailureReporter.report(
                failure,
                app: app,
                context: "scan_completion_webhook"
            )
        } catch {
            app.logger.error("Failed to mark scan \(scanID) as finished: \(error)")
        }
    }

    /// The candidates `plugin` will actually be run against: those whose shape
    /// it declares it can act on (`FootprintPlugin.accepts`), and — for heavy
    /// plugins — only the origins that bound their fan-out.
    ///
    /// Filtering here rather than inside each plugin's `scan` is what makes the
    /// saving real: a skipped pair costs no cache lookup, no `scan` call, and no
    /// empty cache row written back for a plugin that would have returned `[]`
    /// on its first line.
    static func applicableCandidates(
        for plugin: any FootprintPlugin,
        from candidates: [TargetDeriver.Candidate]
    ) -> [TargetDeriver.Candidate] {
        let accepts = plugin.accepts
        return candidates.filter { candidate in
            guard !plugin.heavy || candidate.origin.heavyEligible else { return false }
            return !accepts.isDisjoint(with: TargetShape.shapes(of: candidate.value))
        }
    }

    /// The subset of `plugins` that has at least one candidate to run against
    /// for `input`. Call sites use this to size `ScanProgressTracker` so the
    /// progress bar counts only work that will really happen, instead of
    /// jumping most of the way instantly as the structurally irrelevant
    /// plugins no-op.
    static func applicablePlugins(
        _ plugins: [any FootprintPlugin],
        for input: String
    ) -> [any FootprintPlugin] {
        let candidates = TargetDeriver.candidates(for: input)
        return plugins.filter { !applicableCandidates(for: $0, from: candidates).isEmpty }
    }

    /// Outcome of one plugin's (or the round-wide sentinel's) work inside a
    /// round's `TaskGroup`. Type-scoped (not local to `runRound`) so
    /// `runPlugin` can share it and tests can construct/inspect it via
    /// `runRound`'s return value.
    enum Outcome: Sendable {
        case done(name: String, succeeded: Bool, results: [PluginResult])
        case timeout
    }

    /// Deduplicates findings within one `run()` invocation — round 1 and every
    /// pivot round share a single instance (threaded through by `run()`), so a
    /// pivot round rediscovering a fact already found in round 1 (or an earlier
    /// pivot round) is a no-op rather than a second `Result` row. Actor-isolated
    /// because `runRound`'s plugin tasks execute concurrently.
    ///
    /// Keyed on the plugin's raw `(source, type, rawData)` — checked in
    /// `persist` *before* `origin.note` prefixing is applied, so the same
    /// underlying finding surfaced via a `.primary` candidate (no prefix) and a
    /// `.variant`/`.pivoted` candidate (prefixed) is still recognized as one
    /// finding. Rounds run strictly sequentially in `run()`, so round 1's
    /// higher-confidence `.primary`-origin candidates always populate this
    /// before any pivot round runs — "first occurrence wins" therefore already
    /// favors the higher-confidence origin.
    actor ResultDedupStore {
        private struct Key: Hashable {
            let source: String
            let type: String
            let rawData: String
        }
        private var seen: Set<Key> = []

        /// Returns true the first time this triple is seen, false on every
        /// subsequent occurrence — the caller should skip persisting on false.
        func markSeen(source: String, type: String, rawData: String) -> Bool {
            seen.insert(Key(source: source, type: type, rawData: rawData)).inserted
        }
    }

    /// Runs one plugin's work for a round (looping its candidates sequentially,
    /// cache-checking/scanning/persisting each) racing it against `timeout`. If
    /// the plugin doesn't finish in time, returns `.done(succeeded: false, results: [])`
    /// immediately without waiting for it — whatever it already persisted for
    /// earlier candidates stays in the DB (see `persist`), but it is abandoned
    /// for this round's `collected`/pivot-mining pool. Swift cannot forcibly
    /// preempt a running `async` function, so the abandoned task keeps running
    /// cooperatively in the background until its own next cancellation
    /// checkpoint — same character as the round-wide deadline this backstops,
    /// not a new risk class.
    static func runPlugin(
        _ plugin: any FootprintPlugin,
        name pName: String,
        cacheTTL pTTL: TimeInterval,
        candidates pCandidates: [TargetDeriver.Candidate],
        scanID: UUID,
        app: Application,
        db: Database,
        useCache: Bool,
        dedup: ResultDedupStore,
        timeout: Double
    ) async -> Outcome {
        await withTaskGroup(of: Outcome?.self) { inner in
            inner.addTask {
                do {
                    var produced: [PluginResult] = []
                    for candidate in pCandidates {
                        guard !Task.isCancelled else { break }
                        let cInput = candidate.value
                        let raw: [PluginResult]
                        if useCache, let cached = await PluginCacheStore.lookup(
                            pluginName: pName,
                            input: cInput,
                            on: db,
                            logger: app.logger
                        ) {
                            raw = PluginResultLimits.sanitize(cached)
                        } else {
                            let fresh = try await plugin.scan(input: cInput, on: app)
                            let bounded = PluginResultLimits.sanitize(fresh)
                            if useCache {
                                await PluginCacheStore.store(pluginName: pName, input: cInput, results: bounded, ttl: pTTL, on: db, logger: app.logger)
                            }
                            raw = bounded
                        }
                        for pr in raw where try await persist(pr, origin: candidate.origin, scanID: scanID, dedup: dedup, on: db) {
                            produced.append(pr)
                        }
                    }
                    return .done(name: pName, succeeded: true, results: produced)
                } catch {
                    app.logger.error("Plugin \(pName) failed: \(error)")
                    return .done(name: pName, succeeded: false, results: [])
                }
            }
            inner.addTask {
                try? await Task.sleep(for: .seconds(timeout))
                return nil
            }
            guard let firstElement = await inner.next() else {
                return .done(name: pName, succeeded: false, results: [])
            }
            inner.cancelAll()
            if let outcome = firstElement {
                return outcome
            }
            app.logger.warning("Plugin \(pName) exceeded its \(Int(timeout))s per-plugin timeout; moving on without waiting for it")
            return .done(name: pName, succeeded: false, results: [])
        }
    }

    /// Runs `plugins` over `candidates` concurrently under a round-wide
    /// `deadline` (outer safety net) and a `perPluginTimeout` (so one hung
    /// plugin can't consume the whole round's budget while others are ready to
    /// move on — see `runPlugin`), persists each result (with its candidate
    /// origin, deduplicated via `dedup`), and returns the raw results (for
    /// pivot mining) plus success/failure/timeout aggregates.
    ///
    /// Plugins with no applicable candidate never get a task — they are absent
    /// from the aggregates entirely rather than counted as trivial successes,
    /// so `success + failure` is the number of plugins that genuinely ran.
    static func runRound(
        plugins: [any FootprintPlugin],
        candidates: [TargetDeriver.Candidate],
        scanID: UUID,
        deadline: Double,
        perPluginTimeout: Double,
        reportProgress: Bool,
        app: Application,
        db: Database,
        useCache: Bool,
        dedup: ResultDedupStore
    ) async -> (collected: [PluginResult], success: Int, failure: Int, timedOut: Bool) {

        var collected: [PluginResult] = []
        var success = 0
        var failure = 0
        var timedOut = false

        // Resolve the work up front so `expectedUnits` is derived from the tasks
        // actually spawned — it drives the early `cancelAll()` below, and a stale
        // count would leave the round waiting on the deadline sentinel.
        let work = plugins.compactMap { plugin -> (plugin: any FootprintPlugin, candidates: [TargetDeriver.Candidate])? in
            let applicable = applicableCandidates(for: plugin, from: candidates)
            return applicable.isEmpty ? nil : (plugin, applicable)
        }
        let expectedUnits = work.count
        guard expectedUnits > 0 else { return ([], 0, 0, false) }

        await withTaskGroup(of: Outcome.self) { group in
            group.addTask {
                try? await Task.sleep(for: .seconds(deadline))
                return .timeout
            }

            for (plugin, pCandidates) in work {
                let pName = plugin.name
                let pTTL = plugin.cacheTTL
                group.addTask {
                    guard !Task.isCancelled else { return .done(name: pName, succeeded: false, results: []) }
                    return await Self.runPlugin(
                        plugin, name: pName, cacheTTL: pTTL, candidates: pCandidates,
                        scanID: scanID, app: app, db: db, useCache: useCache,
                        dedup: dedup, timeout: perPluginTimeout
                    )
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

    /// Persists one plugin result, unless `dedup` has already seen an identical
    /// `(source, type, rawData)` triple earlier in this scan — returns `false`
    /// in that case and stores nothing. Derived findings (a username inferred
    /// from an email local-part, or a username variant) get a confidence
    /// discount and a provenance note/marker: the account exists, but its link
    /// to the original target is an inference, not a proven fact — the strength
    /// of which depends on the candidate's `origin`.
    @discardableResult
    private static func persist(_ pr: PluginResult, origin: TargetDeriver.Origin, scanID: UUID, dedup: ResultDedupStore, on db: Database) async throws -> Bool {
        guard await dedup.markSeen(source: pr.source, type: pr.type, rawData: pr.rawData) else {
            return false
        }

        let rawBase = origin.note.map { "\($0) \(pr.rawData)" } ?? pr.rawData
        let cappedRawData = PluginResultLimits.truncateUTF8(
            rawBase, maxBytes: PluginResultLimits.maxRawDataBytes,
            suffix: PluginResultLimits.truncationSuffix
        )

        var metaDict = pr.metadata ?? [:]
        if origin.derived { metaDict["derivedFrom"] = origin.note ?? "derived" }
        let metadataJSON = PluginResultLimits.encodeMetadata(metaDict)

        let confidence = max(0.0, min(1.0, pr.confidenceScore)) * origin.confidenceFactor
        let result = Result(
            scanID: scanID,
            source: PluginResultLimits.truncateUTF8(pr.source, maxBytes: PluginResultLimits.maxSourceBytes),
            type: PluginResultLimits.truncateUTF8(pr.type, maxBytes: PluginResultLimits.maxTypeBytes),
            confidenceScore: confidence,
            rawData: cappedRawData,
            metadata: metadataJSON
        )
        try await ResultStreamStore.persist(result, on: db)
        return true
    }

}

/// Hard storage/cache boundaries for data returned by plugins. Limits are in
/// UTF-8 bytes (the representation sent over HTTP and stored before encryption),
/// never Swift grapheme-cluster counts.
enum PluginResultLimits {
    static let maxResultsPerCandidate = 512
    static let maxSourceBytes = 64
    static let maxTypeBytes = 64
    static let maxRawDataBytes = 8_192
    static let maxMetadataBytes = 4_096
    static let maxCachePayloadBytes = 2 * 1_024 * 1_024
    // AES-GCM adds 28 bytes, then Base64 expands by roughly 4/3. Keep a little
    // envelope headroom while rejecting oversized rows before decryption.
    static let maxStoredCachePayloadBytes = 3 * 1_024 * 1_024
    static let truncationSuffix = "… [truncated]"

    static func sanitize(_ results: [PluginResult]) -> [PluginResult] {
        results.prefix(maxResultsPerCandidate).map { result in
            let metadata = result.metadata.flatMap { encodeMetadata($0) == nil ? nil : $0 }
            return PluginResult(
                source: truncateUTF8(result.source, maxBytes: maxSourceBytes),
                type: truncateUTF8(result.type, maxBytes: maxTypeBytes),
                confidenceScore: result.confidenceScore.isFinite
                    ? max(0, min(1, result.confidenceScore)) : 0,
                rawData: truncateUTF8(
                    result.rawData, maxBytes: maxRawDataBytes, suffix: truncationSuffix
                ),
                metadata: metadata
            )
        }
    }

    static func encodeMetadata(_ metadata: [String: String]) -> String? {
        guard !metadata.isEmpty,
              let data = try? JSONEncoder().encode(metadata),
              data.count <= maxMetadataBytes else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Truncates at a Character boundary, preserving valid Unicode and keeping
    /// the optional suffix inside (not in addition to) the byte budget.
    static func truncateUTF8(_ value: String, maxBytes: Int, suffix: String = "") -> String {
        precondition(maxBytes >= 0)
        guard value.utf8.count > maxBytes else { return value }

        let suffixBytes = suffix.utf8.count
        precondition(suffixBytes <= maxBytes)
        let prefixBudget = maxBytes - suffixBytes
        var used = 0
        var output = ""
        output.reserveCapacity(maxBytes)
        for character in value {
            let bytes = String(character).utf8.count
            guard used + bytes <= prefixBudget else { break }
            output.append(character)
            used += bytes
        }
        output.append(suffix)
        return output
    }
}
