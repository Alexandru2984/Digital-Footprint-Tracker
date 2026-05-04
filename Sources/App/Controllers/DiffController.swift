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

struct DiffController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.get("scans", ":scanID", "diff", ":otherId", use: diff)
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

        func key(for result: Result) -> String {
            "\(result.source):\(result.type):\(result.rawData.prefix(100))"
        }
        func riskLabel(score: Double) -> String {
            score >= 0.8 ? "High" : score >= 0.5 ? "Medium" : "Low"
        }
        func toDiffResult(_ r: Result) -> DiffResultItem {
            DiffResultItem(source: r.source, type: r.type, rawData: r.rawData, risk: riskLabel(score: r.confidenceScore))
        }

        let aMap = Dictionary(grouping: scanA.results, by: key(for:)).mapValues { $0.first! }
        let bMap = Dictionary(grouping: scanB.results, by: key(for:)).mapValues { $0.first! }

        let newResults     = bMap.filter { aMap[$0.key] == nil }.values.map(toDiffResult)
        let removedResults = aMap.filter { bMap[$0.key] == nil }.values.map(toDiffResult)
        let unchanged      = aMap.filter { bMap[$0.key] != nil }.values.map(toDiffResult)

        let infoA = ScanDiffInfo(
            scanID: scanA.id!, input: scanA.input, status: scanA.status.rawValue,
            scannedAt: scanA.createdAt.map { $0.timeIntervalSince1970 },
            resultCount: scanA.results.count
        )
        let infoB = ScanDiffInfo(
            scanID: scanB.id!, input: scanB.input, status: scanB.status.rawValue,
            scannedAt: scanB.createdAt.map { $0.timeIntervalSince1970 },
            resultCount: scanB.results.count
        )

        return DiffResponse(
            scanA: infoA, scanB: infoB,
            new: Array(newResults), removed: Array(removedResults), unchanged: Array(unchanged)
        )
    }
}
