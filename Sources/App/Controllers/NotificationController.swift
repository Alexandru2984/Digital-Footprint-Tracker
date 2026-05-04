import Vapor
import Fluent

struct NotificationController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let r = routes
        r.get("notifications", use: list)
        r.post("notifications", ":id", "read", use: markRead)
        r.post("notifications", "read-all", use: markAllRead)
    }

    @Sendable func list(req: Request) async throws -> [ScanNotification] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        return try await ScanNotification.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .sort(\.$createdAt, .descending)
            .limit(50)
            .all()
    }

    @Sendable func markRead(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let id = req.parameters.get("id", as: UUID.self),
              let notif = try await ScanNotification.find(id, on: req.db) else { throw Abort(.notFound) }
        guard notif.$user.id == user.id! else { throw Abort(.forbidden) }
        notif.isRead = true
        try await notif.save(on: req.db)
        return .ok
    }

    @Sendable func markAllRead(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let unread = try await ScanNotification.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .filter(\.$isRead == false)
            .all()
        for n in unread { n.isRead = true; try await n.save(on: req.db) }
        return .ok
    }
}
