import Fluent
import SQLKit

struct CreateNotificationOutbox: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema(NotificationOutboxEvent.schema)
            .id()
            .field(
                "user_id", .uuid, .required,
                .references(User.schema, "id", onDelete: .cascade)
            )
            .field(
                "scan_id", .uuid,
                .references(Scan.schema, "id", onDelete: .cascade)
            )
            .field("payload", .string, .required)
            .field("idempotency_key_hash", .string, .required)
            .field("created_at", .datetime)
            .unique(on: "user_id", "idempotency_key_hash")
            .create()

        try await database.schema(NotificationDeliveryJob.schema)
            .id()
            .field(
                "event_id", .uuid, .required,
                .references(NotificationOutboxEvent.schema, "id", onDelete: .cascade)
            )
            .field("channel", .string, .required)
            .field("status", .string, .required)
            .field("attempt_count", .int, .required)
            .field("max_attempts", .int, .required)
            .field("next_attempt_at", .datetime, .required)
            .field("lease_owner", .string)
            .field("lease_expires_at", .datetime)
            .field("last_failure_code", .string)
            .field("completed_at", .datetime)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .unique(on: "event_id", "channel")
            .create()

        guard let sql = database as? SQLDatabase else { return }
        try await sql.raw("""
            CREATE INDEX IF NOT EXISTS notification_delivery_jobs_due_idx
            ON notification_delivery_jobs (status, next_attempt_at, created_at)
            """).run()
        try await sql.raw("""
            CREATE INDEX IF NOT EXISTS notification_delivery_jobs_lease_idx
            ON notification_delivery_jobs (status, lease_expires_at)
            """).run()
    }

    func revert(on database: Database) async throws {
        try await database.schema(NotificationDeliveryJob.schema).delete()
        try await database.schema(NotificationOutboxEvent.schema).delete()
    }
}
