import Fluent
import Vapor
import Crypto

final class APIKey: Model, Content {
    static let schema = "api_keys"

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "key_hash") var keyHash: String
    @Field(key: "label") var label: String
    @OptionalField(key: "last_used_at") var lastUsedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(userID: UUID, keyHash: String, label: String) {
        self.$user.id = userID
        self.keyHash = keyHash
        self.label = label
    }

    /// One-time public response returned on key creation (includes raw token).
    struct Created: Content {
        let id: UUID?
        let label: String
        let token: String   // shown only once — not stored
        let keyPreview: String
        let createdAt: Date?
    }

    /// Safe public response for listing (no token, no hash).
    struct Public: Content {
        let id: UUID?
        let label: String
        let keyPreview: String
        let lastUsedAt: Date?
        let createdAt: Date?
    }

    func toPublic(preview: String) -> Public {
        Public(id: id, label: label, keyPreview: preview, lastUsedAt: lastUsedAt, createdAt: createdAt)
    }
}

/// SHA-256 hex digest of an arbitrary string.
func sha256Hex(_ input: String) -> String {
    let digest = SHA256.hash(data: Data(input.utf8))
    return digest.map { String(format: "%02x", $0) }.joined()
}

