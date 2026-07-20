import Fluent
import Vapor

final class AuditLog: Model {
    static let schema = "audit_logs"

    @ID(key: .id) var id: UUID?
    @OptionalField(key: "user_id") var userID: UUID?
    @Field(key: "action") var action: String
    @Field(key: "target") var targetCipher: String
    var target: String {
        get { FieldCrypto.decryptStored(targetCipher) }
        set { targetCipher = FieldCrypto.encrypt(newValue) }
    }
    @Field(key: "ip") var ipCipher: String
    var ip: String {
        get { FieldCrypto.decryptStored(ipCipher) }
        set { ipCipher = FieldCrypto.encrypt(newValue) }
    }
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(userID: UUID?, action: String, target: String, ip: String) {
        self.userID = userID
        self.action = action
        self.target = target
        self.ip = ip
    }
}
