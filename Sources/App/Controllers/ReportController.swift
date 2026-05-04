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

        let scriptPath = Environment.get("REPORT_SCRIPT_PATH")
            ?? "/home/micu/swift+vapor/scripts/generate_report.py"
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            throw Abort(.serviceUnavailable, reason: "Report generation unavailable.")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments    = [scriptPath]
        process.environment  = [
            "PATH":       "/usr/bin:/usr/local/bin",
            "HOME":       "/tmp",
            "PYTHONPATH": Environment.get("HOLEHE_PYTHONPATH") ?? "/home/micu/.local/lib/python3.12/site-packages",
        ]

        let stdinPipe  = Pipe()
        let stdoutPipe = Pipe()
        process.standardInput  = stdinPipe
        process.standardError  = FileHandle.nullDevice
        process.standardOutput = stdoutPipe

        try process.run()
        stdinPipe.fileHandleForWriting.write(jsonData)
        stdinPipe.fileHandleForWriting.closeFile()

        let pdfData: Data = await withCheckedContinuation { cont in
            let sema = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in sema.signal() }

            let killTimer = DispatchWorkItem { if process.isRunning { process.terminate() } }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 30, execute: killTimer)

            DispatchQueue.global(qos: .utility).async {
                sema.wait()
                killTimer.cancel()
                let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                cont.resume(returning: data)
            }
        }

        guard !pdfData.isEmpty else {
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
