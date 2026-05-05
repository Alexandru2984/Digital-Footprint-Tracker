import Vapor
import Fluent
import Crypto

struct APIKeyMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        if request.session.data["userID"] == nil,
           let authHeader = request.headers[.authorization].first,
           authHeader.hasPrefix("Bearer ") {
            let token = String(authHeader.dropFirst("Bearer ".count)).trimmingCharacters(in: .whitespaces)
            if !token.isEmpty {
                let hash = sha256Hex(token)
                if let apiKey = try? await APIKey.query(on: request.db).filter(\.$keyHash == hash).with(\.$user).first() {
                    request.session.data["userID"] = apiKey.$user.id.uuidString
                    let keyID = apiKey.id
                    Task {
                        if let id = keyID,
                           let k = try? await APIKey.find(id, on: request.application.db) {
                            k.lastUsedAt = Date()
                            try? await k.save(on: request.application.db)
                        }
                    }
                }
            }
        }
        return try await next.respond(to: request)
    }
}
