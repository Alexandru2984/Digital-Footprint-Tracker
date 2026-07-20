import Vapor
import Fluent
import Foundation

struct ReportController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let noCache = routes.grouped(NoCacheMiddleware())
        noCache.get("report", ":id", use: generateReport)
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

        // If the scan belongs to a specific user, only that user may download the report.
        // Anonymous scans (no owner) are restricted to admins only.
        if let ownerID = scan.$user.id {
            guard let currentUser = try await req.currentUser(), currentUser.id == ownerID else {
                throw Abort(.forbidden, reason: "Access denied.")
            }
        } else {
            guard let currentUser = try await req.currentUser(), currentUser.isAdmin else {
                throw Abort(.forbidden, reason: "Access denied.")
            }
        }

        // Serialise scan + results to JSON for the Python script.
        let payload: [String: Any] = [
            "scanID":      scan.id?.uuidString ?? "",
            "input":       scan.input,
            "status":      scan.status.rawValue,
            "completedAt": scan.completedAt.map { $0.timeIntervalSince1970 } as Any,
            "scannedAt":   scan.createdAt.map  { $0.timeIntervalSince1970 } as Any,
            "results": scan.results.map { r in [
                "source":          r.source,
                "type":            r.type,
                "confidenceScore": r.confidenceScore,
                "rawData":         r.rawData
            ] as [String: Any] }
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        guard jsonData.count <= 10 * 1_024 * 1_024 else {
            throw Abort(.payloadTooLarge, reason: "Report input exceeded the 10 MB limit.")
        }

        let scriptPath = Environment.get("REPORT_SCRIPT_PATH")
            ?? "/home/micu/swift+vapor/scripts/generate_report.py"
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            throw Abort(.serviceUnavailable, reason: "Report generation unavailable.")
        }

        let execution: BoundedProcess.Result
        do {
            execution = try await BoundedProcess.run(
                executable: "/usr/bin/python3",
                arguments: [scriptPath],
                environment: [
                    "PATH": "/usr/bin:/usr/local/bin",
                    "PYTHONPATH": Environment.get("HOLEHE_PYTHONPATH") ?? "/home/micu/.local/lib/python3.12/site-packages",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "LANG": "C.UTF-8",
                ],
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

        let safeName = scan.input
            .replacingOccurrences(of: "@", with: "_at_")
            .filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/pdf")
        headers.add(name: .contentDisposition, value: "attachment; filename=\"report-\(safeName).pdf\"")
        return Response(status: .ok, headers: headers, body: .init(data: pdfData))
    }
}
