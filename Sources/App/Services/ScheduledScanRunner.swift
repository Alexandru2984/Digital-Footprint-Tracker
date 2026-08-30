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
                await runDueScheduledScansOnce(app: app)
            }
        }
    }
}

/// One bounded scheduler tick. Internal visibility keeps the quarantine path
/// directly regression-testable without booting an endless lifecycle loop.
func runDueScheduledScansOnce(app: Application) async {
    let db = app.db
    let now = Date()
    let due: [ScheduledScan]
    do {
        due = try await ScheduledScan.query(on: db)
            .filter(\.$isActive == true)
            .filter(\.$nextRunAt <= now)
            .limit(20)
            .all()
    } catch {
        app.logger.error("[ScheduledScanRunner] Failed to query scheduled scans: \(error)")
        return
    }

    for ss in due {
        let rawInput: String
        do {
            rawInput = try ss.input
        } catch let failure as FieldCrypto.DecryptionFailure {
            await SensitiveFieldFailureReporter.report(
                failure,
                app: app,
                context: "scheduled_scan"
            )
            // Quarantine this recurring source. Leaving it active would retry the
            // same unreadable ciphertext every minute and create an alert storm.
            ss.isActive = false
            ss.lastRunAt = now
            do {
                try await ss.save(on: db)
            } catch {
                app.logger.error("[ScheduledScanRunner] Failed to quarantine unreadable schedule \(ss.id?.uuidString ?? "unknown").")
            }
            continue
        } catch {
            app.logger.error("[ScheduledScanRunner] Failed to read encrypted schedule input.")
            continue
        }
        let userID = ss.$user.id
        guard let owner = try? await User.find(userID, on: db), owner.emailVerified else {
            app.logger.warning("[ScheduledScanRunner] Disabling schedule \(ss.id?.uuidString ?? "?") for an unverified or missing owner.")
            ss.isActive = false
            try? await ss.save(on: db)
            continue
        }
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
        let scheduleID = ss.id?.uuidString ?? "unknown"
        app.logger.info("[ScheduledScanRunner] Running schedule \(scheduleID).")

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
            await finishScheduledScan(
                scanID: scanID,
                input: input,
                userID: userID,
                scheduleID: scheduleID,
                app: app
            )
        }
    }
}

private func finishScheduledScan(
    scanID: UUID,
    input: String,
    userID: UUID,
    scheduleID: String,
    app: Application
) async {
    let db = app.db
    // Hand plugin execution off to the shared runner: same deadline, registry,
    // persistence and terminal status behavior as interactive scans.
    let plugins = ScanController.backgroundPlugins
    let runnableCount = ScanPluginRunner.applicablePlugins(plugins, for: input).count
    await ScanProgressTracker.shared.start(scanID: scanID, total: runnableCount)
    // Monitor mode deliberately bypasses cache so upstream changes remain visible.
    await ScanPluginRunner.run(
        scanID: scanID,
        input: input,
        plugins: plugins,
        app: app,
        useCache: false,
        pivotDepth: 0
    )

    let allResults = (try? await App.Result.query(on: db)
        .filter(\.$scan.$id == scanID).all()) ?? []
    let previousScan = try? await Scan.query(on: db)
        .filterInput(input)
        .filter(\.$user.$id == userID)
        .filter(\.$statusRaw == "completed")
        .filter(\.$id != scanID)
        .sort(\.$createdAt, .descending)
        .first()
    var firedDiffAlert = false

    do {
        if let prev = previousScan, let prevID = prev.id {
            let prevResults = (try? await App.Result.query(on: db)
                .filter(\.$scan.$id == prevID).all()) ?? []
            let prevFingerprints = Set(try prevResults.map {
                "\($0.source):\($0.type):\(String(try $0.rawData.prefix(200)))"
            })
            let newResults = try allResults.filter { result in
                !prevFingerprints.contains(
                    "\(result.source):\(result.type):\(String(try result.rawData.prefix(200)))"
                )
            }
            let toInput: (App.Result) throws -> IdentitySynthesizer.Input = {
                IdentitySynthesizer.Input(
                    source: $0.source,
                    type: $0.type,
                    confidence: $0.confidenceScore,
                    metadata: try $0.metadataObject ?? [:],
                    rawData: try $0.rawData
                )
            }
            let exposureDelta = ExposureDiff.between(
                previous: try prevResults.map(toInput),
                current: try allResults.map(toInput)
            )
            let exposureLine = exposureDelta.hasExposureChange ? exposureDelta.headline : ""
            if !newResults.isEmpty {
                var seen = Set<String>()
                let distinctSources = newResults
                    .map { $0.source }
                    .filter { seen.insert($0).inserted }
                let preview = distinctSources.prefix(5).joined(separator: ", ")
                let remainder = max(0, distinctSources.count - 5)
                let sourceLine = remainder > 0 ? "\(preview), +\(remainder) more" : preview
                let message = exposureLine.isEmpty
                    ? "🆕 \(newResults.count) new finding\(newResults.count == 1 ? "" : "s") for \u{201C}\(String(input.prefix(30)))\u{201D}: \(sourceLine)"
                    : "🚨 New exposure for \u{201C}\(String(input.prefix(30)))\u{201D}: \(exposureLine)"
                let notification = ScanNotification(
                    userID: userID,
                    scanID: scanID,
                    message: message,
                    newResultsCount: newResults.count
                )
                try? await notification.save(on: db)

                if (try? await User.find(userID, on: db)) != nil {
                    let risk = try RiskScorer.compute(results: allResults)
                    var body = "Your monitored target '\(input)' has \(newResults.count) new result(s).\n"
                    if !exposureLine.isEmpty { body += "New exposure: \(exposureLine)\n" }
                    body += "Sources: \(sourceLine)\nRisk: \(risk.level.rawValue) (\(risk.value)/100)."
                    let title = exposureLine.isEmpty
                        ? "Monitor Alert [\(risk.level.rawValue)]: \(newResults.count) new for \(String(input.prefix(30)))"
                        : "🚨 Exposure Alert [\(risk.level.rawValue)]: \(String(input.prefix(30)))"
                    _ = try await NotificationOutbox.enqueue(
                        userID: userID,
                        title: title,
                        message: body,
                        scanID: scanID,
                        idempotencyKey: "scheduled-diff:\(scanID.uuidString.lowercased())",
                        app: app
                    )
                    firedDiffAlert = true
                }
                let logMessage = "[ScheduledScanRunner] Schedule \(scheduleID): "
                    + "\(newResults.count) new finding(s); "
                    + "exposure_changed=\(!exposureLine.isEmpty)"
                app.logger.info("\(logMessage)")
            }
        }

        if !firedDiffAlert,
           let user = try? await User.find(userID, on: db),
           user.verboseAlerts {
            let risk = try RiskScorer.compute(results: allResults)
            _ = try await NotificationOutbox.enqueue(
                userID: userID,
                title: "Scheduled Scan Complete: \(String(input.prefix(30)))",
                message: "Scheduled scan for '\(input)' completed with \(allResults.count) result(s). Risk: \(risk.level.rawValue) (\(risk.value)/100).",
                scanID: scanID,
                idempotencyKey: "scheduled-complete:\(scanID.uuidString.lowercased())",
                app: app
            )
        }
    } catch let failure as FieldCrypto.DecryptionFailure {
        await SensitiveFieldFailureReporter.report(
            failure,
            app: app,
            context: "scheduled_scan_diff"
        )
    } catch {
        app.logger.error("[ScheduledScanRunner] Schedule \(scheduleID): diff processing failed.")
    }
}
