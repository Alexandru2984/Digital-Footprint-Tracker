import Fluent
import Vapor

enum ScanStatus: String, Codable {
    case pending
    case completed
    case failed
}

final class Scan: Model, Content {
    static let schema = "scans"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "input")
    var input: String

    @Field(key: "status")
    var statusRaw: String

    var status: ScanStatus {
        get { ScanStatus(rawValue: statusRaw) ?? .pending }
        set { statusRaw = newValue.rawValue }
    }

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @OptionalField(key: "completed_at")
    var completedAt: Date?

    @Children(for: \.$scan)
    var results: [Result]

    @OptionalParent(key: "user_id")
    var user: User?

    @Siblings(through: ScanTag.self, from: \.$scan, to: \.$tag)
    var tags: [Tag]

    init() { }

    init(id: UUID? = nil, input: String, status: ScanStatus = .pending, userID: UUID? = nil) {
        self.id = id
        self.input = input
        self.statusRaw = status.rawValue
        self.$user.id = userID
    }
}
