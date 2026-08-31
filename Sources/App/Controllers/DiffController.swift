import Vapor
import Fluent

struct DiffResultItem: Content {
    let source: String
    let type: String
    let rawData: String
    let risk: String
}

struct ScanDiffInfo: Content {
    let scanID: UUID
    let input: String
    let status: String
    let scannedAt: Double?
    let resultCount: Int
}

struct DiffResponse: Content {
    let scanA: ScanDiffInfo
    let scanB: ScanDiffInfo
    let new: [DiffResultItem]
    let removed: [DiffResultItem]
    let unchanged: [DiffResultItem]
}

struct ExposureDiffResponse: Content {
    let current: ScanDiffInfo
    let previous: ScanDiffInfo?
    let delta: ExposureDiff.Delta
}

struct DiffController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
            .grouped(ScanRateLimiter(anonMax: 20, authedMax: 120, windowSeconds: 60))
        noCache.get("scans", ":scanID", "diff", ":otherId", use: diff)
        noCache.get("scans", ":scanID", "exposure-diff", use: exposureDiff)
    }

    /// GET /scans/:scanID/exposure-diff — the attack-surface delta (new/closed ports,
    /// new/resolved CVEs, new/removed subdomains, posture grade shifts) versus the
    /// previous completed scan of the same target. Owner-only. `previous` is null on a
    /// first scan, in which case `delta` is empty (no baseline to compare against).
    @Sendable
    func exposureDiff(req: Request) async throws -> ExposureDiffResponse {
        guard let user = try await req.currentUser(), let userID = user.id else {
            throw Abort(.unauthorized, reason: "Authentication required.")
        }
        guard let idStr = req.parameters.get("scanID"), let id = UUID(uuidString: idStr) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db)
            .filter(\.$id == id).filter(\.$user.$id == userID)
            .with(\.$results).first() else {
            throw Abort(.notFound, reason: "Scan not found or not owned by you.")
        }

        var query = Scan.query(on: req.db)
            .filterInput(try scan.input)
            .filter(\.$user.$id == userID)
            .filter(\.$statusRaw == "completed")
            .filter(\.$id != id)
        if let created = scan.createdAt { query = query.filter(\.$createdAt < created) }
        let previous = try await query.sort(\.$createdAt, .descending).with(\.$results).first()

        let curInputs = try Self.inputs(from: scan.results)
        let delta: ExposureDiff.Delta
        let previousInfo: ScanDiffInfo?
        if let previous {
            delta = ExposureDiff.between(
                previous: try Self.inputs(from: previous.results),
                current: curInputs
            )
            previousInfo = try Self.info(previous)
        } else {
            delta = .empty
            previousInfo = nil
        }

        return ExposureDiffResponse(
            current: try Self.info(scan),
            previous: previousInfo,
            delta: delta
        )
    }

    private static func inputs(from results: [Result]) throws -> [IdentitySynthesizer.Input] {
        try results.map {
            IdentitySynthesizer.Input(source: $0.source, type: $0.type, confidence: $0.confidenceScore,
                                      metadata: try $0.metadataObject ?? [:], rawData: try $0.rawData)
        }
    }

    private static func info(_ scan: Scan) throws -> ScanDiffInfo {
        ScanDiffInfo(scanID: scan.id!, input: try scan.input, status: scan.status.rawValue,
                     scannedAt: scan.createdAt.map { $0.timeIntervalSince1970 },
                     resultCount: scan.results.count)
    }

    @Sendable
    func diff(req: Request) async throws -> DiffResponse {
        guard let user = try await req.currentUser() else {
            throw Abort(.unauthorized, reason: "Authentication required.")
        }
        guard let userID = user.id else {
            throw Abort(.internalServerError)
        }
        guard let scanIdStr = req.parameters.get("scanID"),
              let scanId = UUID(uuidString: scanIdStr),
              let otherIdStr = req.parameters.get("otherId"),
              let otherId = UUID(uuidString: otherIdStr) else {
            throw Abort(.badRequest, reason: "Invalid scan IDs.")
        }

        guard let scanA = try await Scan.query(on: req.db)
            .filter(\.$id == scanId)
            .filter(\.$user.$id == userID)
            .with(\.$results)
            .first() else {
            throw Abort(.notFound, reason: "Scan A not found or not owned by you.")
        }

        guard let scanB = try await Scan.query(on: req.db)
            .filter(\.$id == otherId)
            .filter(\.$user.$id == userID)
            .with(\.$results)
            .first() else {
            throw Abort(.notFound, reason: "Scan B not found or not owned by you.")
        }

        func key(for result: Result) throws -> String {
            "\(result.source):\(result.type):\(try result.rawData.prefix(100))"
        }
        func riskLabel(score: Double) -> String {
            score >= 0.8 ? "High" : score >= 0.5 ? "Medium" : "Low"
        }
        func toDiffResult(_ r: Result) throws -> DiffResultItem {
            DiffResultItem(source: r.source, type: r.type, rawData: try r.rawData, risk: riskLabel(score: r.confidenceScore))
        }

        var aMap: [String: Result] = [:]
        for result in scanA.results {
            let resultKey = try key(for: result)
            if aMap[resultKey] == nil { aMap[resultKey] = result }
        }
        var bMap: [String: Result] = [:]
        for result in scanB.results {
            let resultKey = try key(for: result)
            if bMap[resultKey] == nil { bMap[resultKey] = result }
        }

        let newResults = try bMap.filter { aMap[$0.key] == nil }.values.map(toDiffResult)
        let removedResults = try aMap.filter { bMap[$0.key] == nil }.values.map(toDiffResult)
        let unchanged = try aMap.filter { bMap[$0.key] != nil }.values.map(toDiffResult)

        let infoA = ScanDiffInfo(
            scanID: scanA.id!, input: try scanA.input, status: scanA.status.rawValue,
            scannedAt: scanA.createdAt.map { $0.timeIntervalSince1970 },
            resultCount: scanA.results.count
        )
        let infoB = ScanDiffInfo(
            scanID: scanB.id!, input: try scanB.input, status: scanB.status.rawValue,
            scannedAt: scanB.createdAt.map { $0.timeIntervalSince1970 },
            resultCount: scanB.results.count
        )

        return DiffResponse(
            scanA: infoA, scanB: infoB,
            new: Array(newResults), removed: Array(removedResults), unchanged: Array(unchanged)
        )
    }
}
