import Fluent
import Vapor

final class ScheduledScan: Model {
    static let schema = "scheduled_scans"

    enum Interval: String, Codable { case daily, weekly }

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "input") var inputCipher: String
    var input: String {
        get throws {
            try FieldCrypto.decryptStored(inputCipher, field: .scheduledScanInput, recordID: id)
        }
    }
    func setInput(_ newValue: String) {
        inputCipher = FieldCrypto.encrypt(newValue, field: .scheduledScanInput, recordID: encryptionID)
    }
    @Field(key: "interval") var interval: Interval
    @Field(key: "is_active") var isActive: Bool
    @OptionalField(key: "last_run_at") var lastRunAt: Date?
    @Field(key: "next_run_at") var nextRunAt: Date

    init() {}
    init(id: UUID? = nil, userID: UUID, input: String, interval: Interval, nextRunAt: Date) {
        let recordID = id ?? UUID()
        self.id = recordID
        self.$user.id = userID
        self.inputCipher = FieldCrypto.encrypt(input, field: .scheduledScanInput, recordID: recordID)
        self.interval = interval
        self.isActive = true
        self.lastRunAt = nil
        self.nextRunAt = nextRunAt
    }

    private var encryptionID: UUID {
        guard let id else { preconditionFailure("ScheduledScan must have an ID before encryption") }
        return id
    }
}
