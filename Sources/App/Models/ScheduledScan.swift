import Fluent
import Vapor

final class ScheduledScan: Model, Content {
    static let schema = "scheduled_scans"

    enum Interval: String, Codable { case daily, weekly }

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "input") var input: String
    @Field(key: "interval") var interval: Interval
    @Field(key: "is_active") var isActive: Bool
    @OptionalField(key: "last_run_at") var lastRunAt: Date?
    @Field(key: "next_run_at") var nextRunAt: Date

    init() {}
    init(id: UUID? = nil, userID: UUID, input: String, interval: Interval, nextRunAt: Date) {
        self.id = id
        self.$user.id = userID
        self.input = input
        self.interval = interval
        self.isActive = true
        self.lastRunAt = nil
        self.nextRunAt = nextRunAt
    }
}
