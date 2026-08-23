import Fluent
import Vapor

final class AuditLog: Model {
    static let schema = "audit_logs"

    @ID(key: .id) var id: UUID?
    @OptionalField(key: "user_id") var userID: UUID?
    @Field(key: "action") var action: String
    @Field(key: "target") var targetCipher: String
    var target: String {
        get throws {
            try FieldCrypto.decryptStored(targetCipher, field: .auditTarget, recordID: id)
        }
    }
    func setTarget(_ newValue: String) { targetCipher = FieldCrypto.encrypt(newValue) }
    @Field(key: "ip") var ipCipher: String
    var ip: String {
        get throws {
            try FieldCrypto.decryptStored(ipCipher, field: .auditIP, recordID: id)
        }
    }
    func setIP(_ newValue: String) { ipCipher = FieldCrypto.encrypt(newValue) }
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(userID: UUID?, action: String, target: String, ip: String) {
        self.userID = userID
        self.action = action
        self.targetCipher = FieldCrypto.encrypt(target)
        self.ipCipher = FieldCrypto.encrypt(ip)
    }
}
