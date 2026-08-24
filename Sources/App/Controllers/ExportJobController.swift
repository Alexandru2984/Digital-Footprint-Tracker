import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor

struct ExportJobDTO: Content {
    let id: UUID?
    let scanID: UUID
    let format: String
    let status: String
    let progressCompleted: Int
    let progressTotal: Int
    let failureCode: String?
    let cancelRequested: Bool
    let attemptCount: Int
    let createdAt: Date?
    let updatedAt: Date?
    let startedAt: Date?
    let completedAt: Date?
    let expiresAt: Date
    let downloadURL: String?
    let manifestURL: String?

    init(_ job: ExportJob, now: Date = Date()) {
        id = job.id
        scanID = job.$scan.id
        format = job.formatRaw
        status = job.statusRaw
        progressCompleted = job.progressCompleted
        progressTotal = job.progressTotal
        failureCode = job.failureCode
        cancelRequested = job.cancelRequested
        attemptCount = job.attemptCount
        createdAt = job.createdAt
        updatedAt = job.updatedAt
        startedAt = job.startedAt
        completedAt = job.completedAt
        expiresAt = job.expiresAt
        let downloadable = job.status == .completed && job.expiresAt > now
        if downloadable, let id = job.id {
            downloadURL = "/export-jobs/\(id.uuidString.lowercased())/download"
            manifestURL = "/export-jobs/\(id.uuidString.lowercased())/manifest"
        } else {
            downloadURL = nil
            manifestURL = nil
        }
    }
}

struct ExportJobController: RouteCollection {
    struct CreateBody: Content {
        let scanID: UUID
        let format: ExportJobFormat
    }

    func boot(routes: RoutesBuilder) throws {
        let limited = routes
            .grouped(NoCacheMiddleware())
            .grouped(ScanRateLimiter(anonMax: 5, authedMax: 30, windowSeconds: 60))
        limited.post("export-jobs", use: create)
        limited.get("export-jobs", use: list)
        limited.get("export-jobs", ":id", use: detail)
        limited.get("export-jobs", ":id", "manifest", use: manifest)
        limited.get("export-jobs", ":id", "download", use: download)
        limited.post("export-jobs", ":id", "cancel", use: cancel)
    }

    @Sendable
    func create(req: Request) async throws -> Response {
        let user = try await Self.requireAuthorizedUser(req)
        guard let userID = user.id else { throw Abort(.internalServerError) }
        let body = try req.content.decode(CreateBody.self)
        guard let scan = try await Scan.query(on: req.db)
            .filter(\.$id == body.scanID)
            .filter(\.$user.$id == userID)
            .first() else {
            // Owner-filtered lookup deliberately hides cross-tenant existence.
            throw Abort(.notFound, reason: "Scan not found.")
        }
        guard scan.status != .pending else {
            throw Abort(.conflict, reason: "Wait for the scan to finish before exporting it.")
        }

        let configuration = req.application.exportJobConfiguration
        let now = Date()
        let job = try await req.db.transaction { database in
            if let sql = database as? SQLDatabase,
               sql.dialect.name.lowercased().contains("postgres") {
                _ = try await sql.raw("""
                    SELECT id FROM users WHERE id = \(bind: userID) FOR UPDATE
                    """).all()
            }
            let outstanding = try await ExportJob.query(on: database)
                .filter(\.$user.$id == userID)
                .group(.or) { group in
                    group.filter(\.$statusRaw == ExportJobStatus.pending.rawValue)
                    group.filter(\.$statusRaw == ExportJobStatus.processing.rawValue)
                }
                .count()
            guard outstanding < configuration.maxOutstandingPerUser else {
                throw Abort(.tooManyRequests, reason: "Too many export jobs are already in progress.")
            }
            let daily = try await ExportJob.query(on: database)
                .filter(\.$user.$id == userID)
                .filter(\.$createdAt >= now.addingTimeInterval(-86_400))
                .count()
            guard daily < configuration.maxJobsPerUserPerDay else {
                throw Abort(.tooManyRequests, reason: "Daily export-job limit reached.")
            }
            let job = ExportJob(
                userID: userID,
                scanID: body.scanID,
                format: body.format,
                maxAttempts: configuration.maxAttempts,
                expiresAt: now.addingTimeInterval(TimeInterval(configuration.retentionHours * 3_600))
            )
            try await job.save(on: database)
            return job
        }

        await AuditLogger.log(
            req: req,
            action: "create_export_job",
            target: body.scanID.uuidString.lowercased()
        )
        let response = Response(status: .accepted)
        try response.content.encode(ExportJobDTO(job, now: now))
        return response
    }

    @Sendable
    func list(req: Request) async throws -> [ExportJobDTO] {
        let user = try await Self.requireAuthorizedUser(req)
        guard let userID = user.id else { throw Abort(.internalServerError) }
        let requestedLimit = (try? req.query.get(Int.self, at: "limit")) ?? 50
        guard (1...100).contains(requestedLimit) else {
            throw Abort(.badRequest, reason: "limit must be between 1 and 100.")
        }
        let jobs = try await ExportJob.query(on: req.db)
            .filter(\.$user.$id == userID)
            .sort(\.$createdAt, .descending)
            .limit(requestedLimit)
            .all()
        let now = Date()
        return jobs.map { ExportJobDTO($0, now: now) }
    }

    @Sendable
    func detail(req: Request) async throws -> ExportJobDTO {
        let (job, _) = try await Self.requireOwnedJob(req)
        return ExportJobDTO(job)
    }

    @Sendable
    func manifest(req: Request) async throws -> ExportJobManifest {
        let (job, _) = try await Self.requireOwnedJob(req)
        try Self.requireDownloadable(job)
        guard let manifest = try job.manifest,
              manifest.jobID == job.id,
              manifest.scanID == job.$scan.id else {
            throw Abort(.internalServerError, reason: "Export manifest is unavailable.")
        }
        return manifest
    }

    @Sendable
    func download(req: Request) async throws -> Response {
        let (job, _) = try await Self.requireOwnedJob(req)
        try Self.requireDownloadable(job)
        guard let manifest = try job.manifest,
              let data = try job.artifactData,
              manifest.jobID == job.id,
              manifest.scanID == job.$scan.id,
              manifest.artifactBytes == data.count,
              manifest.artifactSHA256 == Self.sha256(data) else {
            throw Abort(.internalServerError, reason: "Export artifact integrity check failed.")
        }

        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: .contentType, value: manifest.contentType)
        headers.replaceOrAdd(
            name: .contentDisposition,
            value: "attachment; filename=\"\(Self.safeFilename(manifest.filename))\""
        )
        headers.replaceOrAdd(name: .cacheControl, value: "private, no-store, max-age=0")
        headers.replaceOrAdd(name: .eTag, value: "\"\(manifest.artifactSHA256)\"")
        headers.replaceOrAdd(name: "X-Content-SHA256", value: manifest.artifactSHA256)
        headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        if job.format == .html {
            headers.replaceOrAdd(
                name: .contentSecurityPolicy,
                value: "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            )
        }
        await AuditLogger.log(
            req: req,
            action: "download_export_job",
            target: job.id?.uuidString.lowercased() ?? "unknown"
        )
        return Response(status: .ok, headers: headers, body: .init(data: data))
    }

    @Sendable
    func cancel(req: Request) async throws -> HTTPStatus {
        let (job, user) = try await Self.requireOwnedJob(req)
        guard let jobID = job.id,
              let userID = user.id,
              let sql = req.db as? SQLDatabase,
              let status = job.status else {
            throw Abort(.internalServerError)
        }
        let now = Date()
        let rows: [any SQLRow]
        switch status {
        case .pending:
            rows = try await sql.raw("""
                UPDATE export_jobs
                SET status = \(bind: ExportJobStatus.cancelled.rawValue),
                    cancel_requested = TRUE,
                    completed_at = \(bind: now),
                    updated_at = \(bind: now)
                WHERE id = \(bind: jobID)
                  AND user_id = \(bind: userID)
                  AND status = \(bind: ExportJobStatus.pending.rawValue)
                RETURNING id
                """).all()
        case .processing:
            rows = try await sql.raw("""
                UPDATE export_jobs
                SET cancel_requested = TRUE,
                    updated_at = \(bind: now)
                WHERE id = \(bind: jobID)
                  AND user_id = \(bind: userID)
                  AND status = \(bind: ExportJobStatus.processing.rawValue)
                RETURNING id
                """).all()
        case .completed, .failed, .cancelled:
            throw Abort(.conflict, reason: "Export job is already terminal.")
        }
        guard !rows.isEmpty else {
            throw Abort(.conflict, reason: "Export job state changed; refresh and retry.")
        }
        await req.application.exportJobWorker.requestCancellation(jobID: jobID)
        await AuditLogger.log(
            req: req,
            action: "cancel_export_job",
            target: jobID.uuidString.lowercased()
        )
        return .accepted
    }

    private static func requireAuthorizedUser(_ req: Request) async throws -> User {
        if req.apiKeyAuthorization != nil {
            guard let user = try await req.currentUser() else {
                throw Abort(.unauthorized, reason: "Authentication required.")
            }
            return user
        }
        return try await req.requireRecentSessionUser()
    }

    private static func requireOwnedJob(_ req: Request) async throws -> (ExportJob, User) {
        let user = try await requireAuthorizedUser(req)
        guard let userID = user.id,
              let id = req.parameters.get("id", as: UUID.self),
              let job = try await ExportJob.query(on: req.db)
                .filter(\.$id == id)
                .filter(\.$user.$id == userID)
                .first() else {
            throw Abort(.notFound, reason: "Export job not found.")
        }
        return (job, user)
    }

    private static func requireDownloadable(_ job: ExportJob) throws {
        guard job.status == .completed else {
            throw Abort(.conflict, reason: "Export artifact is not ready.")
        }
        if job.expiresAt <= Date() {
            throw Abort(.gone, reason: "Export artifact has expired.")
        }
    }

    private static func safeFilename(_ value: String) -> String {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        let scalars = value.unicodeScalars.filter(allowed.contains)
        let result = String(String.UnicodeScalarView(scalars).prefix(120))
        return result.isEmpty ? "export.bin" : result
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
