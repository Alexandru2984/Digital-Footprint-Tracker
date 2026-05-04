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
        let input = ss.input
        let userID = ss.$user.id
        app.logger.info("[ScheduledScanRunner] Running scheduled scan for '\(input)'.")

        let plugins: [any FootprintPlugin] = [
            GravatarPlugin(), HaveIBeenPwnedPlugin(), UsernamePlugin(), GitLabPlugin(),
            RedditPlugin(), TwitterPlugin(), KeybasePlugin(), TelegramPlugin(),
            MastodonPlugin(), HackerNewsPlugin(), SteamPlugin(), NpmPlugin(),
            PyPIPlugin(), PastebinPlugin(), PhonePlugin(), DomainPlugin(),
            BulkUsernamePlugin(), BulkEmailPlugin()
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

                        if let monitorUser = try? await User.find(userID, on: db), let hookURL = monitorUser.webhookURL {
                            let risk = RiskScorer.compute(results: allResults)
                            let newResultDTOs = newResults.prefix(10).map { r -> [String: Any] in
                                ["source": r.source, "type": r.type, "confidenceScore": r.confidenceScore, "rawData": String(r.rawData.prefix(500))]
                            }
                            let monitorPayload: [String: Any] = [
                                "event": "scan.new_findings",
                                "scanID": scanID.uuidString,
                                "input": input,
                                "newResultsCount": newResults.count,
                                "totalResultsCount": allResults.count,
                                "riskScore": risk.value,
                                "riskLevel": risk.level.rawValue,
                                "newResults": Array(newResultDTOs),
                                "completedAt": scan.completedAt.map { $0.timeIntervalSince1970 } as Any
                            ]
                            if let body = try? JSONSerialization.data(withJSONObject: monitorPayload),
                               let url = URL(string: hookURL) {
                                var hookReq = URLRequest(url: url)
                                hookReq.httpMethod = "POST"
                                hookReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
                                hookReq.httpBody = body
                                hookReq.timeoutInterval = 10
                                _ = try? await URLSession.shared.data(for: hookReq)
                            }
                        }
                        app.logger.info("[ScheduledScanRunner] Monitor: \(newResults.count) new findings for '\(input)'")
                    }
                }

                if let user = try? await User.find(userID, on: db), let hookURL = user.webhookURL {
                    let risk = RiskScorer.compute(results: allResults)
                    await fireWebhookScheduled(url: hookURL, scanID: scanID, scan: scan, risk: risk, resultCount: allResults.count, logger: app.logger)
                }
            } catch {
                app.logger.error("[ScheduledScanRunner] Post-scan save error: \(error)")
            }
        }
    }
}

private func fireWebhookScheduled(url: String, scanID: UUID, scan: Scan, risk: RiskScorer.Score, resultCount: Int, logger: Logger) async {
    guard let hookURL = URL(string: url) else { return }
    let payload: [String: Any] = [
        "event": "scheduled_scan.completed",
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
    do { _ = try await URLSession.shared.data(for: request) }
    catch { logger.warning("Scheduled webhook to \(url) failed: \(error)") }
}
