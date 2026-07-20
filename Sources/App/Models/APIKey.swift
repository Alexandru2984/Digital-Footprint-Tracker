import Fluent
import Vapor
import Crypto

final class APIKey: Model, Content {
    static let schema = "api_keys"

    enum Scope: String, Codable, CaseIterable, Sendable {
        case scansRead = "scans:read"
        case scansWrite = "scans:write"
        case automationRead = "automation:read"
        case automationWrite = "automation:write"
        case investigationsRead = "investigations:read"
        case investigationsWrite = "investigations:write"
    }

    static let defaultScopes: Set<Scope> = [.scansRead, .scansWrite]
    static let defaultScopesRaw = defaultScopes.map(\.rawValue).sorted().joined(separator: ",")

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "key_hash") var keyHash: String
    @Field(key: "label") var label: String
    @Field(key: "scopes") var scopesRaw: String
    @OptionalField(key: "expires_at") var expiresAt: Date?
    @OptionalField(key: "last_used_at") var lastUsedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(userID: UUID, keyHash: String, label: String,
         scopes: Set<Scope> = APIKey.defaultScopes, expiresAt: Date) {
        self.$user.id = userID
        self.keyHash = keyHash
        self.label = label
        self.scopesRaw = scopes.map(\.rawValue).sorted().joined(separator: ",")
        self.expiresAt = expiresAt
    }

    var scopes: Set<Scope> {
        Set(scopesRaw.split(separator: ",").compactMap { Scope(rawValue: String($0)) })
    }

    /// One-time public response returned on key creation (includes raw token).
    struct Created: Content {
        let id: UUID?
        let label: String
        let token: String   // shown only once — not stored
        let keyPreview: String
        let scopes: [String]
        let expiresAt: Date?
        let createdAt: Date?
    }

    /// Safe public response for listing (no token, no hash).
    struct Public: Content {
        let id: UUID?
        let label: String
        let keyPreview: String
        let scopes: [String]
        let expiresAt: Date?
        let lastUsedAt: Date?
        let createdAt: Date?
    }

    func toPublic(preview: String) -> Public {
        Public(id: id, label: label, keyPreview: preview,
               scopes: scopes.map(\.rawValue).sorted(), expiresAt: expiresAt,
               lastUsedAt: lastUsedAt, createdAt: createdAt)
    }
}

/// SHA-256 hex digest of an arbitrary string.
func sha256Hex(_ input: String) -> String {
    let digest = SHA256.hash(data: Data(input.utf8))
    return digest.map { String(format: "%02x", $0) }.joined()
}
