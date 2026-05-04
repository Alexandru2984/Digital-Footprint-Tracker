import Vapor
import Fluent
import Foundation

struct APIKeyController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let r = routes.grouped("auth").grouped(NoCacheMiddleware())
        r.get("api-keys", use: list)
        r.post("api-keys", use: create)
        r.delete("api-keys", ":id", use: delete)
    }

    @Sendable func list(req: Request) async throws -> [APIKey] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        return try await APIKey.query(on: req.db).filter(\.$user.$id == user.id!).all()
    }

    @Sendable func create(req: Request) async throws -> APIKey {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        struct Body: Content { let label: String }
        let body = try req.content.decode(Body.self)
        guard body.label.count >= 1, body.label.count <= 50 else {
            throw Abort(.badRequest, reason: "Label must be 1–50 characters.")
        }
        let count = try await APIKey.query(on: req.db).filter(\.$user.$id == user.id!).count()
        guard count < 5 else { throw Abort(.tooManyRequests, reason: "Maximum 5 API keys per account.") }

        let key = APIKey(userID: user.id!, key: UUID().uuidString.replacingOccurrences(of: "-", with: ""), label: body.label)
        try await key.save(on: req.db)
        return key
    }

    @Sendable func delete(req: Request) async throws -> HTTPStatus {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        guard let id = req.parameters.get("id", as: UUID.self),
              let key = try await APIKey.find(id, on: req.db) else { throw Abort(.notFound) }
        guard key.$user.id == user.id! else { throw Abort(.forbidden) }
        try await key.delete(on: req.db)
        return .noContent
    }
}
