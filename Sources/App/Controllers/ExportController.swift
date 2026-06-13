import Vapor
import Fluent

struct ExportController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("export", ":id", use: exportJSON)
        routes.get("export", ":id", "graph", use: exportGraphML)
    }

    @Sendable
    func exportJSON(req: Request) async throws -> Response {
        guard let idStr = req.parameters.get("id"), let scanID = UUID(uuidString: idStr) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db).filter(\.$id == scanID).with(\.$results).first() else {
            throw Abort(.notFound, reason: "Scan not found.")
        }
        // Owned scans are owner-only; anonymous scans are readable by anyone
        // holding the unguessable scanID (capability access).
        try await scan.authorizeRead(req)
        AuditLogger.log(req: req, action: "export_json", target: scan.input)

        let risk = RiskScorer.compute(results: scan.results)
        let payload: [String: Any] = [
            "scanID": scan.id?.uuidString ?? "",
            "input": scan.input,
            "status": scan.status.rawValue,
            "riskScore": risk.value,
            "riskLevel": risk.level.rawValue,
            "scannedAt": scan.createdAt.map { $0.timeIntervalSince1970 } as Any,
            "completedAt": scan.completedAt.map { $0.timeIntervalSince1970 } as Any,
            "results": scan.results.map { r -> [String: Any] in
                var row: [String: Any] = [
                    "id": r.id?.uuidString ?? "",
                    "source": r.source,
                    "type": r.type,
                    "confidenceScore": r.confidenceScore,
                    "rawData": r.rawData
                ]
                if let meta = r.metadataObject { row["metadata"] = meta }
                return row
            }
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/json; charset=utf-8")
        headers.add(name: .contentDisposition, value: "attachment; filename=\"export-\(Self.safeName(scan.input)).json\"")
        return Response(status: .ok, headers: headers, body: .init(data: jsonData))
    }

    /// GET /export/:id/graph — the synthesized identity as a GraphML relationship
    /// graph (Gephi / yEd / Cytoscape / Maltego). Same capability rules as the rest.
    @Sendable
    func exportGraphML(req: Request) async throws -> Response {
        guard let idStr = req.parameters.get("id"), let scanID = UUID(uuidString: idStr) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db).filter(\.$id == scanID).with(\.$results).first() else {
            throw Abort(.notFound, reason: "Scan not found.")
        }
        try await scan.authorizeRead(req)
        AuditLogger.log(req: req, action: "export_graphml", target: scan.input)

        let xml = IdentityGraph.graphml(from: scan.synthesizedIdentity(), target: scan.input)
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/graphml+xml; charset=utf-8")
        headers.add(name: .contentDisposition, value: "attachment; filename=\"graph-\(Self.safeName(scan.input)).graphml\"")
        return Response(status: .ok, headers: headers, body: .init(string: xml))
    }

    /// Filesystem-safe filename fragment derived from the scan input.
    private static func safeName(_ input: String) -> String {
        input
            .replacingOccurrences(of: "@", with: "_at_")
            .filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
    }
}
