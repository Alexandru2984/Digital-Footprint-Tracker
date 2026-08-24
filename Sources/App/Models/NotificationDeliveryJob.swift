import Fluent
import Foundation

enum NotificationDeliveryJobStatus: String, Codable, CaseIterable, Sendable {
    case pending
    case processing
    case succeeded
    case skipped
    case deadLetter = "dead_letter"

    var isTerminal: Bool {
        self == .succeeded || self == .skipped || self == .deadLetter
    }
}

final class NotificationDeliveryJob: Model {
    static let schema = "notification_delivery_jobs"

    @ID(key: .id) var id: UUID?
    @Parent(key: "event_id") var event: NotificationOutboxEvent
    @Field(key: "channel") var channelRaw: String
    @Field(key: "status") var statusRaw: String
    @Field(key: "attempt_count") var attemptCount: Int
    @Field(key: "max_attempts") var maxAttempts: Int
    @Field(key: "next_attempt_at") var nextAttemptAt: Date
    @OptionalField(key: "lease_owner") var leaseOwner: String?
    @OptionalField(key: "lease_expires_at") var leaseExpiresAt: Date?
    @OptionalField(key: "last_failure_code") var lastFailureCode: String?
    @OptionalField(key: "completed_at") var completedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?
    @Timestamp(key: "updated_at", on: .update) var updatedAt: Date?

    init() {}

    var channel: NotificationChannel? { NotificationChannel(rawValue: channelRaw) }
    var status: NotificationDeliveryJobStatus? { NotificationDeliveryJobStatus(rawValue: statusRaw) }
}
