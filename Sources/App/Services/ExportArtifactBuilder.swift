import Crypto
import Fluent
import Foundation
import Vapor

enum ExportArtifactBuilder {
    enum BuildError: Error, Equatable, Sendable {
        case invalidJob
        case sourceIncomplete
        case resultLimitExceeded
        case sourceTooLarge
        case artifactTooLarge
        case reportUnavailable
        case reportFailed
        case cancelledOrLeaseLost

        var failureCode: String {
            switch self {
            case .invalidJob: return "invalid_job_reference"
            case .sourceIncomplete: return "source_incomplete"
            case .resultLimitExceeded: return "result_limit_exceeded"
            case .sourceTooLarge: return "source_too_large"
            case .artifactTooLarge: return "artifact_too_large"
            case .reportUnavailable: return "report_unavailable"
            case .reportFailed: return "report_failed"
            case .cancelledOrLeaseLost: return "cancelled_or_lease_lost"
            }
        }
    }

    struct BuiltArtifact: Sendable {
        let data: Data
        let manifest: ExportJobManifest
    }

    private struct Finding: Codable, Sendable {
        let id: UUID?
        let source: String
        let type: String
        let confidenceScore: Double
        let rawData: String
        let metadata: [String: String]?
    }

    private struct Provenance: Codable, Sendable {
        let schemaVersion: Int
        let generatedAt: Double
        let sourceComplete: Bool
        let resultCount: Int
        let resultSetSHA256: String
    }

    private struct JSONDocument: Codable, Sendable {
        let scanID: UUID
        let input: String
        let status: String
        let riskScore: Int
        let riskLevel: String
        let scannedAt: Double?
        let completedAt: Double?
        let results: [Finding]
        let provenance: Provenance
    }

    typealias Progress = @Sendable (_ completed: Int, _ total: Int) async throws -> Void

    static func build(
        jobID: UUID,
        scanID: UUID,
        format: ExportJobFormat,
        app: Application,
        configuration: ExportJobConfiguration,
        progress: Progress
    ) async throws -> BuiltArtifact {
        guard let scan = try await Scan.find(scanID, on: app.db) else {
            throw BuildError.invalidJob
        }
        guard scan.status != .pending else { throw BuildError.sourceIncomplete }
        let input = try scan.input
        let total = try await Result.query(on: app.db)
            .filter(\.$scan.$id == scanID)
            .count()
        guard total <= configuration.maxResults else {
            throw BuildError.resultLimitExceeded
        }

        try await progress(0, total)
        var cursor: UUID?
        var models: [Result] = []
        var findings: [Finding] = []
        var sourceBytes = input.utf8.count
        guard sourceBytes <= configuration.maxSourceBytes else {
            throw BuildError.sourceTooLarge
        }
        models.reserveCapacity(total)
        findings.reserveCapacity(total)

        while true {
            let query = Result.query(on: app.db)
                .filter(\.$scan.$id == scanID)
                .sort(\.$id, .ascending)
                .limit(configuration.batchSize)
            if let cursor { query.filter(\.$id > cursor) }
            let page = try await query.all()
            guard !page.isEmpty else { break }

            for result in page {
                let rawData = try result.rawData
                let metadata = try result.metadataObject
                let rowBytes = result.source.utf8.count
                    + result.type.utf8.count
                    + rawData.utf8.count
                    + (try result.metadata?.utf8.count ?? 0)
                guard rowBytes <= configuration.maxSourceBytes - min(
                    sourceBytes, configuration.maxSourceBytes
                ) else {
                    throw BuildError.sourceTooLarge
                }
                sourceBytes += rowBytes
                models.append(result)
                findings.append(Finding(
                    id: result.id,
                    source: result.source,
                    type: result.type,
                    confidenceScore: result.confidenceScore,
                    rawData: rawData,
                    metadata: metadata
                ))
                guard findings.count <= configuration.maxResults else {
                    throw BuildError.resultLimitExceeded
                }
            }

            guard let lastID = page.last?.id else { throw BuildError.invalidJob }
            cursor = lastID
            try await progress(findings.count, total)
            if page.count < configuration.batchSize { break }
        }

        let canonicalEncoder = JSONEncoder()
        canonicalEncoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let canonicalResults = try canonicalEncoder.encode(findings)
        let resultSetHash = sha256(canonicalResults)
        let generatedAt = Date()
        let sourceComplete = scan.status == .completed
        let risk = try RiskScorer.compute(results: models)
        let inputs = try models.map {
            IdentitySynthesizer.Input(
                source: $0.source,
                type: $0.type,
                confidence: $0.confidenceScore,
                metadata: try $0.metadataObject ?? [:],
                rawData: try $0.rawData
            )
        }
        let profile = IdentitySynthesizer.synthesize(
            from: inputs,
            riskScore: risk.value,
            riskLevel: risk.level.rawValue
        )
        let surface = ExposureDiff.snapshot(from: inputs)
        let safeName = filenameFragment(input)
        let data: Data
        let contentType: String
        let filename: String

        switch format {
        case .json:
            let document = JSONDocument(
                scanID: scanID,
                input: input,
                status: scan.status.rawValue,
                riskScore: risk.value,
                riskLevel: risk.level.rawValue,
                scannedAt: scan.createdAt?.timeIntervalSince1970,
                completedAt: scan.completedAt?.timeIntervalSince1970,
                results: findings,
                provenance: Provenance(
                    schemaVersion: 1,
                    generatedAt: generatedAt.timeIntervalSince1970,
                    sourceComplete: sourceComplete,
                    resultCount: findings.count,
                    resultSetSHA256: resultSetHash
                )
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            data = try encoder.encode(document)
            contentType = "application/json; charset=utf-8"
            filename = "export-\(safeName).json"

        case .graphml:
            let graph = IdentityGraph.graphml(from: profile, target: input)
            data = Data(graph.utf8)
            contentType = "application/graphml+xml; charset=utf-8"
            filename = "graph-\(safeName).graphml"

        case .markdown:
            var markdown = ExecutiveReport.markdown(
                input: input,
                profile: profile,
                surface: surface,
                generatedAt: generatedAt
            )
            markdown += "\n\n## Export provenance\n\n"
            markdown += "- Complete source snapshot: \(sourceComplete ? "yes" : "no")\n"
            markdown += "- Exported results: \(findings.count)\n"
            markdown += "- Result-set SHA-256: `\(resultSetHash)`\n"
            data = Data(markdown.utf8)
            contentType = "text/markdown; charset=utf-8"
            filename = "report-\(safeName).md"

        case .html:
            data = Data(ExecutiveReportHTML.html(
                input: input,
                profile: profile,
                surface: surface,
                generatedAt: generatedAt
            ).utf8)
            contentType = "text/html; charset=utf-8"
            filename = "report-\(safeName).html"

        case .pdf:
            let source = JSONDocument(
                scanID: scanID,
                input: input,
                status: scan.status.rawValue,
                riskScore: risk.value,
                riskLevel: risk.level.rawValue,
                scannedAt: scan.createdAt?.timeIntervalSince1970,
                completedAt: scan.completedAt?.timeIntervalSince1970,
                results: findings,
                provenance: Provenance(
                    schemaVersion: 1,
                    generatedAt: generatedAt.timeIntervalSince1970,
                    sourceComplete: sourceComplete,
                    resultCount: findings.count,
                    resultSetSHA256: resultSetHash
                )
            )
            let sourceData = try canonicalEncoder.encode(source)
            guard sourceData.count <= configuration.maxSourceBytes else {
                throw BuildError.sourceTooLarge
            }
            data = try await renderPDF(
                source: sourceData,
                maxBytes: configuration.maxArtifactBytes,
                app: app
            )
            contentType = "application/pdf"
            filename = "report-\(safeName).pdf"
        }

        guard data.count <= configuration.maxArtifactBytes else {
            throw BuildError.artifactTooLarge
        }
        try await progress(total, total)
        let artifactHash = sha256(data)
        return BuiltArtifact(
            data: data,
            manifest: ExportJobManifest(
                schemaVersion: 1,
                jobID: jobID,
                scanID: scanID,
                format: format,
                sourceStatus: scan.status.rawValue,
                sourceCreatedAt: scan.createdAt,
                sourceCompletedAt: scan.completedAt,
                generatedAt: generatedAt,
                resultCount: findings.count,
                resultSetSHA256: resultSetHash,
                artifactSHA256: artifactHash,
                artifactBytes: data.count,
                contentType: contentType,
                filename: filename,
                complete: sourceComplete
            )
        )
    }

    private static func renderPDF(
        source: Data,
        maxBytes: Int,
        app: Application
    ) async throws -> Data {
        let bundledScript = URL(fileURLWithPath: app.directory.workingDirectory)
            .appendingPathComponent("scripts", isDirectory: true)
            .appendingPathComponent("generate_report.py", isDirectory: false)
            .path
        let scriptPath = Environment.get("REPORT_SCRIPT_PATH") ?? bundledScript
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            throw BuildError.reportUnavailable
        }
        var processEnvironment = [
            "PATH": "/usr/bin:/usr/local/bin",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "LANG": "C.UTF-8",
        ]
        if let pythonPath = Environment.get("REPORT_PYTHONPATH"), !pythonPath.isEmpty {
            processEnvironment["PYTHONPATH"] = pythonPath
        }
        let execution: BoundedProcess.Result
        do {
            execution = try await BoundedProcess.run(
                executable: Environment.get("REPORT_PYTHON_PATH") ?? "/usr/bin/python3",
                arguments: [scriptPath],
                environment: processEnvironment,
                stdin: source,
                timeout: 30,
                maxOutputBytes: maxBytes
            )
        } catch is CancellationError {
            throw BuildError.cancelledOrLeaseLost
        } catch {
            throw BuildError.reportUnavailable
        }
        if execution.outputExceeded { throw BuildError.artifactTooLarge }
        guard execution.succeeded,
              execution.stdout.starts(with: Data("%PDF-".utf8)) else {
            throw BuildError.reportFailed
        }
        return execution.stdout
    }

    private static func filenameFragment(_ input: String) -> String {
        let value = input
            .replacingOccurrences(of: "@", with: "_at_")
            .filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        return String(value.prefix(80)).isEmpty ? "scan" : String(value.prefix(80))
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
