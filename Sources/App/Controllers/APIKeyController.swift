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
        let user = try await req.requireSessionUser()
        let keys = try await APIKey.query(on: req.db).filter(\.$user.$id == user.id!).all()
        // The preview field was historically the first 8 chars of the SHA-256
        // key hash — that's 32 bits of the hash leaking into a list endpoint
        // for no functional gain (users identify keys by label). Replaced with
        // an opaque mask so we never expose hash material via /api/auth/api-keys.
        return keys.map { k in k.toPublic(preview: "•••") }
    }

    @Sendable func create(req: Request) async throws -> APIKey.Created {
        let user = try await req.requireRecentSessionUser()
        struct Body: Content {
            let label: String
            let scopes: [String]?
            let expiresInDays: Int?
        }
        let body = try req.content.decode(Body.self)
        let label = body.label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard label.count >= 1, label.count <= 50 else {
            throw Abort(.badRequest, reason: "Label must be 1–50 characters.")
        }
        let requestedScopes = body.scopes ?? APIKey.defaultScopes.map(\.rawValue)
        let scopes = Set(requestedScopes.compactMap(APIKey.Scope.init(rawValue:)))
        guard !scopes.isEmpty, scopes.count == requestedScopes.count else {
            throw Abort(.badRequest, reason: "At least one valid, unique API key scope is required.")
        }
        let expiresInDays = body.expiresInDays ?? 90
        guard (1...365).contains(expiresInDays) else {
            throw Abort(.badRequest, reason: "API keys must expire in 1–365 days.")
        }
        let count = try await APIKey.query(on: req.db).filter(\.$user.$id == user.id!).count()
        guard count < 5 else { throw Abort(.tooManyRequests, reason: "Maximum 5 API keys per account.") }

        let rawToken = UUID().uuidString.replacingOccurrences(of: "-", with: "")
            + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let hash = sha256Hex(rawToken)
        let expiresAt = Date().addingTimeInterval(TimeInterval(expiresInDays * 86_400))
        let key = APIKey(userID: user.id!, keyHash: hash, label: label,
                         scopes: scopes, expiresAt: expiresAt)
        try await key.save(on: req.db)
        await AuditLogger.log(req: req, action: "api_key_created", target: label)
        return APIKey.Created(
            id: key.id,
            label: key.label,
            token: rawToken,
            keyPreview: "•••",
            scopes: key.scopes.map(\.rawValue).sorted(),
            expiresAt: key.expiresAt,
            createdAt: key.createdAt
        )
    }

    @Sendable func delete(req: Request) async throws -> HTTPStatus {
        let user = try await req.requireRecentSessionUser()
        guard let id = req.parameters.get("id", as: UUID.self),
              let key = try await APIKey.find(id, on: req.db) else { throw Abort(.notFound) }
        guard key.$user.id == user.id! else { throw Abort(.forbidden) }
        let label = key.label
        try await key.delete(on: req.db)
        await AuditLogger.log(req: req, action: "api_key_deleted", target: label)
        return .noContent
    }
}
