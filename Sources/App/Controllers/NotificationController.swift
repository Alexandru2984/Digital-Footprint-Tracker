import Vapor
import Fluent

struct ScanNotificationDTO: Content {
    let id: UUID?
    let scanID: UUID
    let message: String
    let newResultsCount: Int
    let isRead: Bool
    let createdAt: Date?

    init(_ notification: ScanNotification) {
        id = notification.id
        scanID = notification.scanID
        message = notification.message
        newResultsCount = notification.newResultsCount
        isRead = notification.isRead
        createdAt = notification.createdAt
    }
}

struct NotificationController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let r = routes
        r.get("notifications", use: list)
        r.post("notifications", ":id", "read", use: markRead)
        r.post("notifications", "read-all", use: markAllRead)
    }

    @Sendable func list(req: Request) async throws -> [ScanNotificationDTO] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let notifications = try await ScanNotification.query(on: req.db)
            .filter(\.$user.$id == user.id!)
            .sort(\.$createdAt, .descending)
            .limit(50)
            .all()
        return notifications.map(ScanNotificationDTO.init)
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
