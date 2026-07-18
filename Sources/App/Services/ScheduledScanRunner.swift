import Vapor
import Fluent
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct ScheduledScanRunner: LifecycleHandler {
    func didBoot(_ application: Application) throws {
        application.logger.info("[ScheduledScanRunner] Starting background scheduler.")
        let app = application
        Task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 60 * 1_000_000_000) // 1-minute tick
                await runDueScans(app: app)
            }
        }
    }
}

private func runDueScans(app: Application) async {
    let db = app.db
    let now = Date()
    let due: [ScheduledScan]
    do {
        due = try await ScheduledScan.query(on: db)
            .filter(\.$isActive == true)
            .filter(\.$nextRunAt <= now)
            .all()
    } catch {
        app.logger.error("[ScheduledScanRunner] Failed to query scheduled scans: \(error)")
        return
    }

    for ss in due {
        let rawInput = ss.input
        let userID = ss.$user.id
        // Defense in depth: re-validate the stored input every cycle. Rows
        // inserted before validation was added (or via direct DB writes) are
        // skipped here instead of being dispatched to plugins.
        let input: String
        do {
            input = try InputValidator.validateScanInput(rawInput)
        } catch {
            app.logger.warning("[ScheduledScanRunner] Skipping scan \(ss.id?.uuidString ?? "?") — input failed validation: \(error)")
            // Advance the schedule so we don't busy-loop on this row.
            ss.lastRunAt = now
            ss.nextRunAt = ss.interval == .daily
                ? now.addingTimeInterval(86400)
                : now.addingTimeInterval(604800)
            try? await ss.save(on: db)
            continue
        }
        app.logger.info("[ScheduledScanRunner] Running scheduled scan for '\(input)'.")

        let newScan = Scan(input: input)
        newScan.$user.id = userID
        do {
            try await newScan.save(on: db)
        } catch {
            app.logger.error("[ScheduledScanRunner] Failed to save scan: \(error)")
            continue
        }
        let scanID = newScan.id!

        // Update timing before running so we don't requeue on crash.
        ss.lastRunAt = now
        ss.nextRunAt = ss.interval == .daily
            ? now.addingTimeInterval(86400)
            : now.addingTimeInterval(604800)
        try? await ss.save(on: db)

        // Detach so we can keep dispatching other due scans without waiting
        // for plugin execution to finish.
        Task {
            // Hand plugin execution off to the shared runner: same 120 s
            // deadline as /scan and /scan/bulk, same plugin registry,
            // results saved and status flipped to .completed / .failed
            // automatically. Avoids the previous bespoke TaskGroup which
            // had no timeout and could hang a scheduled scan forever.
            let plugins = ScanController.defaultPlugins
            await ScanProgressTracker.shared.start(scanID: scanID, total: plugins.count)
            // Bypass the plugin cache: monitor mode must see the live state of
            // each upstream so net-new findings can be diffed against the
            // previous run. Cached results would silently mask new accounts /
            // breaches / abuse reports surfaced since the last scan.
            await ScanPluginRunner.run(scanID: scanID, input: input, plugins: plugins, app: app, useCache: false)

            // Monitor-mode diff and per-channel notifications are
            // scheduled-scan specific, so they run here after the shared
            // runner has finished persisting results and marking status.
            let allResults = (try? await App.Result.query(on: db).filter(\.$scan.$id == scanID).all()) ?? []

            // Monitor mode: diff against the previous completed scan for the
            // same (input, user) pair and notify on net-new findings.
            let previousScan = try? await Scan.query(on: db)
                .filterInput(input)
                .filter(\.$user.$id == userID)
                .filter(\.$statusRaw == "completed")
                .filter(\.$id != scanID)
                .sort(\.$createdAt, .descending)
                .first()

            // Whether monitor mode emitted a diff alert this cycle. Used to
            // suppress the verbose "complete" alert below — no need to ping
            // the user twice for the same run.
            var firedDiffAlert = false

            if let prev = previousScan, let prevID = prev.id {
                let prevResults = (try? await App.Result.query(on: db).filter(\.$scan.$id == prevID).all()) ?? []
                let prevFingerprints = Set(prevResults.map { "\($0.source):\($0.type):\(String($0.rawData.prefix(200)))" })
                let newResults = allResults.filter { r in
                    !prevFingerprints.contains("\(r.source):\(r.type):\(String(r.rawData.prefix(200)))")
                }
                // Attack-surface delta: lead the alert with newly opened ports / CVEs /
                // subdomains when present — far more actionable than a source list.
                let toInput: (App.Result) -> IdentitySynthesizer.Input = {
                    IdentitySynthesizer.Input(source: $0.source, type: $0.type, confidence: $0.confidenceScore,
                                              metadata: $0.metadataObject ?? [:], rawData: $0.rawData)
                }
                let exposureDelta = ExposureDiff.between(previous: prevResults.map(toInput), current: allResults.map(toInput))
                let exposureLine = exposureDelta.hasExposureChange ? exposureDelta.headline : ""
                if !newResults.isEmpty {
                    // Build an actionable summary line: the top distinct sources
                    // where new findings appeared, capped to keep messages short
                    // enough for Telegram + SMS-style channels. Order-preserving
                    // dedup so the highest-confidence source surfaces first.
                    var seen = Set<String>()
                    let distinctSources = newResults
                        .map { $0.source }
                        .filter { seen.insert($0).inserted }
                    let preview = distinctSources.prefix(5).joined(separator: ", ")
                    let remainder = max(0, distinctSources.count - 5)
                    let sourceLine = remainder > 0 ? "\(preview), +\(remainder) more" : preview

                    let notification = ScanNotification(
                        userID: userID,
                        scanID: scanID,
                        message: exposureLine.isEmpty
                            ? "🆕 \(newResults.count) new finding\(newResults.count == 1 ? "" : "s") for \u{201C}\(String(input.prefix(30)))\u{201D}: \(sourceLine)"
                            : "🚨 New exposure for \u{201C}\(String(input.prefix(30)))\u{201D}: \(exposureLine)",
                        newResultsCount: newResults.count
                    )
                    try? await notification.save(on: db)

                    if let monitorUser = try? await User.find(userID, on: db) {
                        let risk = RiskScorer.compute(results: allResults)
                        var body = "Your monitored target '\(input)' has \(newResults.count) new result(s).\n"
                        if !exposureLine.isEmpty { body += "New exposure: \(exposureLine)\n" }
                        body += "Sources: \(sourceLine)\nRisk: \(risk.level.rawValue) (\(risk.value)/100)."
                        let title = exposureLine.isEmpty
                            ? "Monitor Alert [\(risk.level.rawValue)]: \(newResults.count) new for \(String(input.prefix(30)))"
                            : "🚨 Exposure Alert [\(risk.level.rawValue)]: \(String(input.prefix(30)))"
                        await NotificationDispatcher.notify(
                            user: monitorUser,
                            title: title,
                            message: body,
                            scanID: scanID,
                            app: app
                        )
                        firedDiffAlert = true
                    }
                    let logSummary = exposureLine.isEmpty ? sourceLine : exposureLine
                    app.logger.info("[ScheduledScanRunner] Monitor: \(newResults.count) new findings for '\(input)' — \(logSummary)")
                }
            }

            // Completion notification — silent by default. Users who actually
            // want a per-run heartbeat opt-in via `verboseAlerts`. This stops
            // the per-target-per-day spam that the unconditional notify was
            // producing for everyone (one alert per scheduled target per run,
            // regardless of whether anything changed).
            if !firedDiffAlert,
               let user = try? await User.find(userID, on: db),
               user.verboseAlerts {
                let risk = RiskScorer.compute(results: allResults)
                await NotificationDispatcher.notify(
                    user: user,
                    title: "Scheduled Scan Complete: \(String(input.prefix(30)))",
                    message: "Scheduled scan for '\(input)' completed with \(allResults.count) result(s). Risk: \(risk.level.rawValue) (\(risk.value)/100).",
                    scanID: scanID,
                    app: app
                )
            }
        }
    }
}
