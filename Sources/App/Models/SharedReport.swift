import Fluent
import Vapor

final class SharedReport: Model, Content {
    static let schema = "shared_reports"

    @ID(key: .id) var id: UUID?
    @Field(key: "scan_id") var scanID: UUID
    @Field(key: "token") var token: String
    @OptionalField(key: "expires_at") var expiresAt: Date?
    @OptionalField(key: "password_hash") var passwordHash: String?
    @Field(key: "view_count") var viewCount: Int
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}

    init(id: UUID? = nil, scanID: UUID, token: String, expiresAt: Date? = nil, passwordHash: String? = nil) {
        self.id = id
        self.scanID = scanID
        self.token = token
        self.expiresAt = expiresAt
        self.passwordHash = passwordHash
        self.viewCount = 0
    }
}
