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

        let plugins: [any FootprintPlugin] = [
            GravatarPlugin(), HaveIBeenPwnedPlugin(), UsernamePlugin(), GitLabPlugin(),
            RedditPlugin(), TwitterPlugin(), KeybasePlugin(), TelegramPlugin(),
            MastodonPlugin(), HackerNewsPlugin(), SteamPlugin(), NpmPlugin(),
            PyPIPlugin(), PastebinPlugin(), PhonePlugin(), DomainPlugin(),
            BulkUsernamePlugin(), BulkEmailPlugin(),
            CrtShPlugin(), WhoisPlugin(), ShodanPlugin()
        ]

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

        Task {
            var allResults: [App.Result] = []
            await withTaskGroup(of: [App.Result].self) { group in
                for plugin in plugins {
                    group.addTask {
                        let name = plugin.name
                        do {
                            let hits = try await plugin.scan(input: input, on: app)
                            return hits.map { App.Result(scanID: scanID, source: name, type: $0.type, confidenceScore: $0.confidenceScore, rawData: $0.rawData) }
                        } catch {
                            return []
                        }
                    }
                }
                for await r in group { allResults += r }
            }
            do {
                for r in allResults { try await r.save(on: db) }
                let scan = try await Scan.find(scanID, on: db)!
                scan.status = allResults.isEmpty ? .failed : .completed
                scan.completedAt = Date()
                try await scan.save(on: db)

                // Monitor mode: diff against previous scan for same input+user
                let previousScan = try? await Scan.query(on: db)
                    .filter(\.$input == input)
                    .filter(\.$user.$id == userID)
                    .filter(\.$statusRaw == "completed")
                    .filter(\.$id != scanID)
                    .sort(\.$createdAt, .descending)
                    .first()

                if let prev = previousScan, let prevID = prev.id {
                    let prevResults = (try? await App.Result.query(on: db).filter(\.$scan.$id == prevID).all()) ?? []
                    let prevFingerprints = Set(prevResults.map { "\($0.source):\($0.type):\(String($0.rawData.prefix(200)))" })
                    let newResults = allResults.filter { r in
                        !prevFingerprints.contains("\(r.source):\(r.type):\(String(r.rawData.prefix(200)))")
                    }
                    if !newResults.isEmpty {
                        let notification = ScanNotification(
                            userID: userID,
                            scanID: scanID,
                            message: "🆕 \(newResults.count) new finding\(newResults.count == 1 ? "" : "s") for \u{201C}\(String(input.prefix(30)))\u{201D}",
                            newResultsCount: newResults.count
                        )
                        try? await notification.save(on: db)

                        if let monitorUser = try? await User.find(userID, on: db) {
                            let risk = RiskScorer.compute(results: allResults)
                            await NotificationDispatcher.notify(
                                user: monitorUser,
                                title: "Monitor Alert: New results for \(String(input.prefix(30)))",
                                message: "Your monitored target '\(input)' has \(newResults.count) new result(s). Risk: \(risk.level.rawValue) (\(risk.value)/100).",
                                scanID: scanID,
                                app: app
                            )
                        }
                        app.logger.info("[ScheduledScanRunner] Monitor: \(newResults.count) new findings for '\(input)'")
                    }
                }

                if let user = try? await User.find(userID, on: db) {
                    let risk = RiskScorer.compute(results: allResults)
                    await NotificationDispatcher.notify(
                        user: user,
                        title: "Scheduled Scan Complete: \(String(input.prefix(30)))",
                        message: "Scheduled scan for '\(input)' completed with \(allResults.count) result(s). Risk: \(risk.level.rawValue) (\(risk.value)/100).",
                        scanID: scanID,
                        app: app
                    )
                }
            } catch {
                app.logger.error("[ScheduledScanRunner] Post-scan save error: \(error)")
            }
        }
    }
}
