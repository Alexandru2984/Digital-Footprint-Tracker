import Vapor
import Fluent

struct ExportController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("export", ":id", use: exportJSON)
        routes.get("export", ":id", "graph", use: exportGraphML)
        routes.get("export", ":id", "report", use: exportReport)
        routes.get("export", ":id", "report.html", use: exportReportHTML)
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
        await AuditLogger.log(req: req, action: "export_json", target: scan.input)

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
        await AuditLogger.log(req: req, action: "export_graphml", target: scan.input)

        let xml = IdentityGraph.graphml(from: scan.synthesizedIdentity(), target: scan.input)
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/graphml+xml; charset=utf-8")
        headers.add(name: .contentDisposition, value: "attachment; filename=\"graph-\(Self.safeName(scan.input)).graphml\"")
        return Response(status: .ok, headers: headers, body: .init(string: xml))
    }

    /// GET /export/:id/report — a shareable Markdown executive report: identity,
    /// attack surface (hosts → ports/CVEs, posture, subdomains), breaches and risk.
    /// Same capability rules as the rest; pure Swift, no Python/subprocess dependency.
    @Sendable
    func exportReport(req: Request) async throws -> Response {
        guard let idStr = req.parameters.get("id"), let scanID = UUID(uuidString: idStr) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db).filter(\.$id == scanID).with(\.$results).first() else {
            throw Abort(.notFound, reason: "Scan not found.")
        }
        try await scan.authorizeRead(req)
        await AuditLogger.log(req: req, action: "export_report", target: scan.input)

        let (profile, surface) = Self.reportModel(for: scan)
        let md = ExecutiveReport.markdown(input: scan.input, profile: profile, surface: surface, generatedAt: Date())
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "text/markdown; charset=utf-8")
        headers.add(name: .contentDisposition, value: "attachment; filename=\"report-\(Self.safeName(scan.input)).md\"")
        return Response(status: .ok, headers: headers, body: .init(string: md))
    }

    /// GET /export/:id/report.html — the same executive report as a self-contained,
    /// print-ready HTML document (browser "Save as PDF"). Inline so it opens in a tab.
    @Sendable
    func exportReportHTML(req: Request) async throws -> Response {
        guard let idStr = req.parameters.get("id"), let scanID = UUID(uuidString: idStr) else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }
        guard let scan = try await Scan.query(on: req.db).filter(\.$id == scanID).with(\.$results).first() else {
            throw Abort(.notFound, reason: "Scan not found.")
        }
        try await scan.authorizeRead(req)
        await AuditLogger.log(req: req, action: "export_report_html", target: scan.input)

        let (profile, surface) = Self.reportModel(for: scan)
        let html = ExecutiveReportHTML.html(input: scan.input, profile: profile, surface: surface, generatedAt: Date())
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "text/html; charset=utf-8")
        // This document needs only its embedded CSS. A report contains data from
        // untrusted remote sources, so give it a defense-in-depth sandbox that
        // prevents scripts, network beacons, navigation bases, and form posts.
        headers.replaceOrAdd(
            name: .contentSecurityPolicy,
            value: "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
        headers.replaceOrAdd(name: "X-Robots-Tag", value: "noindex, nofollow, noarchive")
        return Response(status: .ok, headers: headers, body: .init(string: html))
    }

    /// Builds the synthesized identity and attack-surface snapshot for a scan's
    /// results — shared by the Markdown and HTML report renderers.
    private static func reportModel(for scan: Scan) -> (IdentitySynthesizer.IdentityProfile, ExposureDiff.Snapshot) {
        let risk = RiskScorer.compute(results: scan.results)
        let inputs = scan.results.map {
            IdentitySynthesizer.Input(source: $0.source, type: $0.type, confidence: $0.confidenceScore,
                                      metadata: $0.metadataObject ?? [:], rawData: $0.rawData)
        }
        let profile = IdentitySynthesizer.synthesize(from: inputs, riskScore: risk.value, riskLevel: risk.level.rawValue)
        return (profile, ExposureDiff.snapshot(from: inputs))
    }

    /// Filesystem-safe filename fragment derived from the scan input.
    private static func safeName(_ input: String) -> String {
        input
            .replacingOccurrences(of: "@", with: "_at_")
            .filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
    }
}
