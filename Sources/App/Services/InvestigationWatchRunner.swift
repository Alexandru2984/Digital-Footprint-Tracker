import Vapor
import Fluent
import Foundation

/// Background monitor for "watched" investigation boards. On a periodic tick it
/// re-scans each due board's active entities, merges any net-new nodes/edges into
/// the stored graph (flagged `new`), and pings the owner's notification channels.
///
/// This is the graph-native counterpart to `ScheduledScanRunner`: instead of
/// watching a single target, it watches a whole investigation and shows you
/// exactly what grew.
struct InvestigationWatchRunner: LifecycleHandler {
    func didBoot(_ application: Application) throws {
        application.logger.info("[InvestigationWatch] Starting board monitor.")
        let app = application
        Task {
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 300 * 1_000_000_000) // 5-minute tick
                await runDue(app: app)
            }
        }
    }

    /// Cap on how many entities a single board re-scans per cycle, so a huge board
    /// can't spawn dozens of scans at once.
    static let maxEntitiesPerBoard = 3
}

private func runDue(app: Application) async {
    let db = app.db
    let now = Date()
    let due: [Investigation]
    do {
        due = try await Investigation.query(on: db)
            .filter(\.$watched == true)
            .filter(\.$nextCheckAt <= now)
            .limit(20)
            .all()
    } catch {
        app.logger.error("[InvestigationWatch] query failed: \(error)")
        return
    }
    for board in due {
        await checkBoard(board, app: app, now: now)
    }
}

private func checkBoard(_ board: Investigation, app: Application, now: Date) async {
    let db = app.db
    let boardID = board.id?.uuidString ?? "?"
    let userID = board.$user.id

    guard let owner = try? await User.find(userID, on: db), owner.emailVerified else {
        board.watched = false
        board.nextCheckAt = nil
        try? await board.save(on: db)
        app.logger.warning("[InvestigationWatch] board \(boardID): disabled for unverified or missing owner.")
        return
    }

    // Advance the schedule up front so a crash mid-check doesn't busy-loop.
    let step: TimeInterval = (board.watchInterval == "weekly") ? 604_800 : 86_400
    board.lastCheckedAt = now
    board.nextCheckAt = now.addingTimeInterval(step)
    do {
        try await board.save(on: db)
    } catch {
        app.logger.error("[InvestigationWatch] board \(boardID): failed to advance schedule: \(error)")
        return
    }

    guard var graph = BoardGraph.decode(board.data) else {
        app.logger.warning("[InvestigationWatch] board \(boardID): unparseable graph, skipping.")
        return
    }
    // Re-scan the board's active fringe: pivotable entities the user seeded or
    // expanded. Cap to keep the workload bounded.
    let targets = graph.nodes
        .filter { n in
            guard let et = n.etype, BoardGraph.pivotable.contains(et) else { return false }
            return (n.root == true) || (n.expanded == true)
        }
        .prefix(InvestigationWatchRunner.maxEntitiesPerBoard)
    guard !targets.isEmpty else { return }

    var totalNew = 0
    var lastScanID: UUID?
    for node in targets {
        let input: String
        do { input = try InputValidator.validateScanInput(node.id) }
        catch { continue } // skip anything that no longer validates as a target

        let scan = Scan(input: input, userID: userID)
        do { try await scan.save(on: db) } catch { continue }
        guard let scanID = scan.id else { continue }
        lastScanID = scanID

        // Fresh data (bypass cache) so net-new findings actually surface.
        await ScanPluginRunner.run(scanID: scanID, input: input,
                                   plugins: ScanController.backgroundPlugins, app: app,
                                   useCache: false, pivotDepth: 0)

        let results = (try? await App.Result.query(on: db).filter(\.$scan.$id == scanID).all()) ?? []
        let inputs = results.map {
            BoardGraph.ResultInput(source: $0.source, type: $0.type, rawData: $0.rawData, metadata: $0.metadataObject ?? [:])
        }
        let extracted = BoardGraph.extract(rootId: node.id, results: inputs)
        totalNew += BoardGraph.merge(into: &graph, nodes: extracted.nodes, edges: extracted.edges)
    }

    guard totalNew > 0 else {
        app.logger.info("[InvestigationWatch] board \(boardID): no changes.")
        return
    }

    // Persist the grown graph (the `new` flags ride along for the UI).
    if let json = BoardGraph.encode(graph),
       json.utf8.count <= InvestigationController.maxDataBytes,
       graph.nodes.count <= InvestigationController.maxNodes,
       graph.edges.count <= InvestigationController.maxEdges {
        board.data = json
        do {
            try await board.save(on: db)
        } catch {
            app.logger.error("[InvestigationWatch] board \(boardID): failed to persist graph: \(error)")
            return
        }
    } else {
        app.logger.warning("[InvestigationWatch] board \(boardID): growth exceeds board limits; changes not persisted.")
        return
    }

    // Alert the owner across their configured channels.
    let newLabels = graph.nodes.filter { $0.new == true }.prefix(6).compactMap { $0.label ?? $0.id }
    let sample = newLabels.joined(separator: ", ")
    await NotificationDispatcher.notify(
        user: owner,
        title: "🕸 Board grew: \(board.name)",
        message: "Your watched investigation \u{201C}\(board.name)\u{201D} has \(totalNew) new entit\(totalNew == 1 ? "y" : "ies").\(sample.isEmpty ? "" : "\nNew: \(sample)")",
        scanID: lastScanID,
        app: app
    )
    app.logger.info("[InvestigationWatch] board \(boardID): +\(totalNew) new entities.")
}
