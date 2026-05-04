import Fluent
import Vapor

final class AuditLog: Model, Content {
    static let schema = "audit_logs"

    @ID(key: .id) var id: UUID?
    @OptionalField(key: "user_id") var userID: UUID?
    @Field(key: "action") var action: String
    @Field(key: "target") var target: String
    @Field(key: "ip") var ip: String
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(userID: UUID?, action: String, target: String, ip: String) {
        self.userID = userID
        self.action = action
        self.target = target
        self.ip = ip
    }
}
