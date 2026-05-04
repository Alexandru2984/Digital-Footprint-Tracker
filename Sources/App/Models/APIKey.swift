import Fluent
import Vapor

final class APIKey: Model, Content {
    static let schema = "api_keys"

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "key") var key: String
    @Field(key: "label") var label: String
    @OptionalField(key: "last_used_at") var lastUsedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(userID: UUID, key: String, label: String) {
        self.$user.id = userID
        self.key = key
        self.label = label
    }
}
