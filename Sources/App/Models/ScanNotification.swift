import Fluent
import Vapor

final class ScanNotification: Model {
    static let schema = "scan_notifications"

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "scan_id") var scanID: UUID
    @Field(key: "message") var messageCipher: String
    var message: String {
        get { FieldCrypto.decryptStored(messageCipher) }
        set { messageCipher = FieldCrypto.encrypt(newValue) }
    }
    @Field(key: "new_results_count") var newResultsCount: Int
    @Field(key: "is_read") var isRead: Bool
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(userID: UUID, scanID: UUID, message: String, newResultsCount: Int) {
        self.$user.id = userID
        self.scanID = scanID
        self.message = message
        self.newResultsCount = newResultsCount
        self.isRead = false
    }
}
