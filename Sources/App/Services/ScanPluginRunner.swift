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

    static func run(scanID: UUID, input: String, plugins: [any FootprintPlugin], app: Application) async {
        // In the test environment there are no external services to reach,
        // and the background URLSession calls generate SIGPIPE when the app
        // shuts down immediately after the test. Skip execution entirely.
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

    private static func fireWebhook(url: String, scanID: UUID, scan: Scan, risk: RiskScorer.Score, resultCount: Int, logger: Logger) async {
        guard let hookURL = URL(string: url) else { return }
        guard !SSRFGuard.isInternalURL(hookURL) else {
            logger.warning("Webhook delivery to \(url) blocked: internal/private target.")
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
}
