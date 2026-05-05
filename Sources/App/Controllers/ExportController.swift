import Vapor
import Fluent

struct ExportController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("export", ":id", use: exportJSON)
    }

    @Sendable
    func exportJSON(req: Request) async throws -> Response {
        guard let idStr = req.parameters.get("id"), let scanID = UUID(uuidString: idStr) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db).filter(\.$id == scanID).with(\.$results).first() else {
            throw Abort(.notFound, reason: "Scan not found.")
        }
        // Enforce ownership: only the scan's owner may export it.
        // Anonymous scans (no owner) are restricted to admins only.
        if let ownerID = scan.$user.id {
            guard let me = try await req.currentUser(), me.id == ownerID else {
                throw Abort(.forbidden, reason: "Access denied.")
            }
        } else {
            guard let me = try await req.currentUser(), me.isAdmin else {
                throw Abort(.forbidden, reason: "Access denied.")
            }
        }
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
            "results": scan.results.map { r in [
                "id": r.id?.uuidString ?? "",
                "source": r.source,
                "type": r.type,
                "confidenceScore": r.confidenceScore,
                "rawData": r.rawData
            ] as [String: Any] }
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        let safeName = scan.input
            .replacingOccurrences(of: "@", with: "_at_")
            .filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/json; charset=utf-8")
        headers.add(name: .contentDisposition, value: "attachment; filename=\"export-\(safeName).json\"")
        return Response(status: .ok, headers: headers, body: .init(data: jsonData))
    }
}
