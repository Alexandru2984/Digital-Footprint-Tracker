import Fluent
import Vapor

struct DarkWebInvestigationController: RouteCollection {
    struct StatusResponse: Content {
        let enabled: Bool
        let workerHealthy: Bool
        let retentionHours: Int
        let maxOutstandingJobs: Int
        let maxJobsPerUserPerDay: Int
    }

    struct Summary: Content {
        let id: String
        let target: String
        let targetKind: String
        let status: String
        let resultCount: Int
        let failureCode: String?
        let cancelRequested: Bool
        let createdAt: Double?
        let startedAt: Double?
        let completedAt: Double?
        let expiresAt: Double
    }

    struct Detail: Content {
        let id: String
        let target: String
        let targetKind: String
        let status: String
        let resultCount: Int
        let failureCode: String?
        let cancelRequested: Bool
        let result: DarkWebWorkerResult?
        let createdAt: Double?
        let startedAt: Double?
        let completedAt: Double?
        let expiresAt: Double
    }

    struct CreateBody: Content {
        let target: String
        let acknowledgedAuthorizedUse: Bool
    }

    func boot(routes: RoutesBuilder) throws {
        let root = routes.grouped("dark-web")
        root.get("status", use: status)
        root.get("investigations", use: list)
        root.grouped(ScanRateLimiter(anonMax: 0, authedMax: 1, windowSeconds: 60))
            .post("investigations", use: create)
        root.group("investigations", ":id") { one in
            one.get(use: get)
            one.post("cancel", use: cancel)
            one.delete(use: remove)
        }
    }

    @Sendable
    func status(req: Request) async throws -> StatusResponse {
        _ = try await verifiedUser(req)
        let config = req.application.darkWebConfiguration
        let workerHealthy = await DarkWebWorkerClient.isHealthy(
            configuration: config, on: req.application
        )
        return StatusResponse(
            enabled: config.enabled,
            workerHealthy: workerHealthy,
            retentionHours: config.retentionHours,
            maxOutstandingJobs: config.maxOutstandingJobs,
            maxJobsPerUserPerDay: config.maxJobsPerUserPerDay
        )
    }

    @Sendable
    func list(req: Request) async throws -> [Summary] {
        let user = try await verifiedUser(req)
        let jobs = try await DarkWebInvestigation.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .sort(\.$createdAt, .descending)
            .limit(25)
            .all()
        return jobs.map(summary)
    }

    @Sendable
    func create(req: Request) async throws -> Response {
        let user = try await verifiedUser(req, requireRecentAuthentication: true)
        let config = req.application.darkWebConfiguration
        guard config.enabled else {
            throw Abort(.serviceUnavailable, reason: "Dark-web investigations are not enabled on this deployment.")
        }

        let body = try req.content.decode(CreateBody.self)
        guard body.acknowledgedAuthorizedUse else {
            throw Abort(.forbidden,
                        reason: "Confirm that this investigation is authorized and for defensive use.")
        }
        let target = try InputValidator.validateScanInput(body.target)
        guard target.unicodeScalars.allSatisfy(\.isASCII) else {
            throw Abort(.badRequest, reason: "Dark-web targets currently support ASCII characters only.")
        }

        let pending = try await DarkWebInvestigation.query(on: req.db)
            .filter(\.$statusRaw == DarkWebInvestigationStatus.pending.rawValue)
            .count()
        let running = try await DarkWebInvestigation.query(on: req.db)
            .filter(\.$statusRaw == DarkWebInvestigationStatus.running.rawValue)
            .count()
        guard pending + running < config.maxOutstandingJobs else {
            throw Abort(.tooManyRequests, reason: "The dark-web investigation queue is full.")
        }

        let userPending = try await DarkWebInvestigation.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .filter(\.$statusRaw == DarkWebInvestigationStatus.pending.rawValue)
            .count()
        let userRunning = try await DarkWebInvestigation.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .filter(\.$statusRaw == DarkWebInvestigationStatus.running.rawValue)
            .count()
        guard userPending + userRunning == 0 else {
            throw Abort(.conflict, reason: "This account already has an active dark-web investigation.")
        }

        let dailyCount = try await DarkWebInvestigation.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .filter(\.$createdAt >= Date().addingTimeInterval(-86_400))
            .count()
        guard dailyCount < config.maxJobsPerUserPerDay else {
            throw Abort(.tooManyRequests, reason: "Daily dark-web investigation quota reached.")
        }

        let job = DarkWebInvestigation(
            userID: user.id!, target: target, retentionHours: config.retentionHours
        )
        do {
            try await job.save(on: req.db)
        } catch let error as any DatabaseError where error.isConstraintFailure {
            throw Abort(.conflict,
                        reason: "This account already has an active dark-web investigation.")
        }
        await AuditLogger.log(
            req: req,
            action: "dark_web_investigation_create",
            target: job.id?.uuidString ?? "unknown"
        )

        let response = Response(status: .accepted)
        try response.content.encode(detail(job))
        return response
    }

    @Sendable
    func get(req: Request) async throws -> Detail {
        detail(try await owned(req))
    }

    @Sendable
    func cancel(req: Request) async throws -> Detail {
        let job = try await owned(req)
        guard !job.status.isTerminal else { return detail(job) }
        job.cancelRequested = true
        if job.status == .pending {
            job.status = .cancelled
            job.completedAt = Date()
        }
        try await job.save(on: req.db)
        await req.application.darkWebRunner.requestCancellation(
            jobID: job.id!, app: req.application
        )
        await AuditLogger.log(
            req: req,
            action: "dark_web_investigation_cancel",
            target: job.id?.uuidString ?? "unknown"
        )
        return detail(job)
    }

    @Sendable
    func remove(req: Request) async throws -> HTTPStatus {
        let job = try await owned(req)
        guard job.status.isTerminal else {
            throw Abort(.conflict, reason: "Cancel the investigation before deleting it.")
        }
        let jobID = job.id?.uuidString ?? "unknown"
        try await job.delete(on: req.db)
        await AuditLogger.log(req: req, action: "dark_web_investigation_delete", target: jobID)
        return .noContent
    }

    private func summary(_ job: DarkWebInvestigation) -> Summary {
        Summary(
            id: job.id?.uuidString ?? "",
            target: job.target,
            targetKind: job.targetKind.rawValue,
            status: job.status.rawValue,
            resultCount: job.resultCount,
            failureCode: job.failureCode,
            cancelRequested: job.cancelRequested,
            createdAt: job.createdAt?.timeIntervalSince1970,
            startedAt: job.startedAt?.timeIntervalSince1970,
            completedAt: job.completedAt?.timeIntervalSince1970,
            expiresAt: job.expiresAt.timeIntervalSince1970
        )
    }

    private func detail(_ job: DarkWebInvestigation) -> Detail {
        let item = summary(job)
        let result = job.resultJSON.flatMap { stored in
            try? JSONDecoder().decode(DarkWebWorkerResult.self, from: Data(stored.utf8))
        }
        return Detail(
            id: item.id,
            target: item.target,
            targetKind: item.targetKind,
            status: item.status,
            resultCount: item.resultCount,
            failureCode: item.failureCode,
            cancelRequested: item.cancelRequested,
            result: result,
            createdAt: item.createdAt,
            startedAt: item.startedAt,
            completedAt: item.completedAt,
            expiresAt: item.expiresAt
        )
    }

    private func verifiedUser(
        _ req: Request,
        requireRecentAuthentication: Bool = false
    ) async throws -> User {
        guard req.apiKeyAuthorization == nil else {
            throw Abort(.forbidden, reason: "Dark-web investigations require an interactive user session.")
        }
        let user: User
        if requireRecentAuthentication {
            user = try await req.requireRecentSessionUser()
        } else {
            guard let current = try await req.currentUser() else { throw Abort(.unauthorized) }
            user = current
        }
        guard user.emailVerified else {
            throw Abort(.forbidden, reason: "Verify your email before running dark-web investigations.")
        }
        return user
    }

    private func owned(_ req: Request) async throws -> DarkWebInvestigation {
        let user = try await verifiedUser(req)
        guard let rawID = req.parameters.get("id"), let id = UUID(uuidString: rawID) else {
            throw Abort(.badRequest, reason: "Invalid dark-web investigation ID.")
        }
        guard let job = try await DarkWebInvestigation.find(id, on: req.db),
              job.$user.id == user.id else {
            throw Abort(.notFound)
        }
        return job
    }
}
