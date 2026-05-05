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

    @Sendable func list(req: Request) async throws -> [APIKey.Public] {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        let keys = try await APIKey.query(on: req.db).filter(\.$user.$id == user.id!).all()
        // Return preview (first 8 chars of key hash as identifier) but never the hash itself.
        return keys.map { k in k.toPublic(preview: String(k.keyHash.prefix(8)) + "…") }
    }

    @Sendable func create(req: Request) async throws -> APIKey.Created {
        guard let user = try await req.currentUser() else { throw Abort(.unauthorized) }
        struct Body: Content { let label: String }
        let body = try req.content.decode(Body.self)
        guard body.label.count >= 1, body.label.count <= 50 else {
            throw Abort(.badRequest, reason: "Label must be 1–50 characters.")
        }
        let count = try await APIKey.query(on: req.db).filter(\.$user.$id == user.id!).count()
        guard count < 5 else { throw Abort(.tooManyRequests, reason: "Maximum 5 API keys per account.") }

        let rawToken = UUID().uuidString.replacingOccurrences(of: "-", with: "")
            + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let hash = sha256Hex(rawToken)
        let key = APIKey(userID: user.id!, keyHash: hash, label: body.label)
        try await key.save(on: req.db)
        return APIKey.Created(
            id: key.id,
            label: key.label,
            token: rawToken,
            keyPreview: String(hash.prefix(8)) + "…",
            createdAt: key.createdAt
        )
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
