import Vapor
import Fluent

struct ScheduledScanDTO: Content {
    let id: String
    let input: String
    let interval: String
    let isActive: Bool
    let lastRunAt: Double?
    let nextRunAt: Double
    init(_ s: ScheduledScan) throws {
        self.id = s.id?.uuidString ?? ""
        self.input = try s.input
        self.interval = s.interval.rawValue
        self.isActive = s.isActive
        self.lastRunAt = s.lastRunAt.map { $0.timeIntervalSince1970 }
        self.nextRunAt = s.nextRunAt.timeIntervalSince1970
    }
}

struct ScheduledScanController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let ss = routes.grouped("scheduled-scans")
        ss.get(use: list)
        ss.post(use: create)
        ss.group(":id") { r in
            r.delete(use: delete)
            r.patch("toggle", use: toggle)
        }
    }

    @Sendable
    func list(req: Request) async throws -> [ScheduledScanDTO] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let scans = try await ScheduledScan.query(on: req.db).filter(\.$user.$id == user.id!).all()
        return try scans.map(ScheduledScanDTO.init)
    }

    @Sendable
    func create(req: Request) async throws -> ScheduledScanDTO {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard user.emailVerified else {
            throw Abort(.forbidden, reason: "Verify your email before creating scheduled scans.")
        }
        // Per-user cap — without this, a single account can schedule
        // thousands of recurring scans and burn the runner / outbound HTTP
        // quota for every plugin.
        let existingCount = try await ScheduledScan.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .count()
        guard existingCount < 20 else {
            throw Abort(.tooManyRequests, reason: "Maximum 20 scheduled scans per account.")
        }
        struct Body: Content { var input: String; var interval: String }
        let body = try req.content.decode(Body.self)
        // Apply the same SSRF + charset + length checks as `/scan` — without
        // this, a user could schedule recurring scans against private/internal
        // targets that the runner would later execute from the server.
        let input = try InputValidator.validateScanInput(body.input)
        guard let interval = ScheduledScan.Interval(rawValue: body.interval) else {
            throw Abort(.badRequest, reason: "Interval must be 'daily' or 'weekly'.")
        }
        let nextRun: Date = interval == .daily
            ? Date().addingTimeInterval(86400)
            : Date().addingTimeInterval(604800)
        let ss = ScheduledScan(userID: user.id!, input: input, interval: interval, nextRunAt: nextRun)
        try await ss.save(on: req.db)
        return try ScheduledScanDTO(ss)
    }

    @Sendable
    func delete(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let idStr = req.parameters.get("id"), let id = UUID(uuidString: idStr) else { throw Abort(.badRequest) }
        guard let ss = try await ScheduledScan.find(id, on: req.db), ss.$user.id == user.id else { throw Abort(.notFound) }
        try await ss.delete(on: req.db)
        return .noContent
    }

    @Sendable
    func toggle(req: Request) async throws -> ScheduledScanDTO {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let idStr = req.parameters.get("id"), let id = UUID(uuidString: idStr) else { throw Abort(.badRequest) }
        guard let ss = try await ScheduledScan.find(id, on: req.db), ss.$user.id == user.id else { throw Abort(.notFound) }
        if !ss.isActive, !user.emailVerified {
            throw Abort(.forbidden, reason: "Verify your email before enabling scheduled scans.")
        }
        ss.isActive.toggle()
        try await ss.save(on: req.db)
        return try ScheduledScanDTO(ss)
    }
}
