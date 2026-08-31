import Vapor
import Fluent
import Foundation

struct ReportController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        // The only endpoint in the application that spawns a subprocess: one
        // request buys up to 30 seconds of Python and 20 MB of output, so it
        // gets the tightest read budget in the app rather than none at all.
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.grouped(ScanRateLimiter(anonMax: 3, authedMax: 10, windowSeconds: 60))
               .get("report", ":id", use: generateReport)
    }

    @Sendable
    func generateReport(req: Request) async throws -> Response {
        guard let idString = req.parameters.get("id"),
              let scanID = UUID(uuidString: idString)
        else {
            throw Abort(.badRequest, reason: "Invalid scan ID.")
        }

        guard let scan = try await Scan.query(on: req.db)
            .filter(\.$id == scanID)
            .with(\.$results)
            .first()
        else {
            throw Abort(.notFound, reason: "Scan not found.")
        }

        // One policy for reading a scan, in one place. This handler used to
        // carry its own copy that made an anonymous scan admin-only while
        // `authorizeRead` made it capability-readable. The divergence protected
        // nothing — `GET /export/:id` already returns the same findings, plus
        // result IDs and metadata, under the capability rule — and it locked a
        // logged-out user out of the report for the scan they had just run.
        try await scan.authorizeRead(req)

        // Serialise scan + results to JSON for the Python script.
        let input = try scan.input
        // Every other export of this data is audited; this one was not.
        await AuditLogger.log(req: req, action: "export_pdf", target: input)
        let payload: [String: Any] = [
            "scanID":      scan.id?.uuidString ?? "",
            "input":       input,
            "status":      scan.status.rawValue,
            "completedAt": scan.completedAt.map { $0.timeIntervalSince1970 } as Any,
            "scannedAt":   scan.createdAt.map  { $0.timeIntervalSince1970 } as Any,
            "results": try scan.results.map { r in [
                "source":          r.source,
                "type":            r.type,
                "confidenceScore": r.confidenceScore,
                "rawData":         try r.rawData
            ] as [String: Any] }
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        guard jsonData.count <= 10 * 1_024 * 1_024 else {
            throw Abort(.payloadTooLarge, reason: "Report input exceeded the 10 MB limit.")
        }

        let bundledScript = URL(fileURLWithPath: req.application.directory.workingDirectory)
            .appendingPathComponent("scripts", isDirectory: true)
            .appendingPathComponent("generate_report.py", isDirectory: false)
            .path
        let scriptPath = Environment.get("REPORT_SCRIPT_PATH") ?? bundledScript
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            throw Abort(.serviceUnavailable, reason: "Report generation unavailable.")
        }

        let execution: BoundedProcess.Result
        do {
            var processEnvironment = [
                "PATH": "/usr/bin:/usr/local/bin",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "LANG": "C.UTF-8",
            ]
            if let pythonPath = Environment.get("REPORT_PYTHONPATH"), !pythonPath.isEmpty {
                processEnvironment["PYTHONPATH"] = pythonPath
            }
            execution = try await BoundedProcess.run(
                executable: Environment.get("REPORT_PYTHON_PATH") ?? "/usr/bin/python3",
                arguments: [scriptPath],
                environment: processEnvironment,
                stdin: jsonData,
                timeout: 30,
                maxOutputBytes: 20 * 1_024 * 1_024
            )
        } catch {
            req.logger.error("Report subprocess could not be started.")
            throw Abort(.serviceUnavailable, reason: "Report generation unavailable.")
        }

        if execution.outputExceeded {
            throw Abort(.payloadTooLarge, reason: "Generated report exceeded the 20 MB limit.")
        }
        let pdfData = execution.stdout
        guard execution.succeeded, pdfData.starts(with: Data("%PDF-".utf8)) else {
            throw Abort(.internalServerError, reason: "Report generation failed.")
        }

        let safeName = input
            .replacingOccurrences(of: "@", with: "_at_")
            .filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/pdf")
        headers.add(name: .contentDisposition, value: "attachment; filename=\"report-\(safeName).pdf\"")
        return Response(status: .ok, headers: headers, body: .init(data: pdfData))
    }
}
