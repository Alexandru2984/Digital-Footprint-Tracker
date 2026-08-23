import Fluent
import Vapor

final class ScanNotification: Model {
    static let schema = "scan_notifications"

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "scan_id") var scanID: UUID
    @Field(key: "message") var messageCipher: String
    var message: String {
        get throws {
            try FieldCrypto.decryptStored(messageCipher, field: .notificationMessage, recordID: id)
        }
    }
    func setMessage(_ newValue: String) {
        messageCipher = FieldCrypto.encrypt(newValue, field: .notificationMessage, recordID: encryptionID)
    }
    @Field(key: "new_results_count") var newResultsCount: Int
    @Field(key: "is_read") var isRead: Bool
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(userID: UUID, scanID: UUID, message: String, newResultsCount: Int) {
        let recordID = UUID()
        self.id = recordID
        self.$user.id = userID
        self.scanID = scanID
        self.messageCipher = FieldCrypto.encrypt(message, field: .notificationMessage, recordID: recordID)
        self.newResultsCount = newResultsCount
        self.isRead = false
    }

    private var encryptionID: UUID {
        guard let id else { preconditionFailure("ScanNotification must have an ID before encryption") }
        return id
    }
}
