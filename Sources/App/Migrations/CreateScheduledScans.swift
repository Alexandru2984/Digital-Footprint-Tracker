import Fluent
struct CreateScheduledScans: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("scheduled_scans")
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("input", .string, .required)
            .field("interval", .string, .required)
            .field("is_active", .bool, .required)
            .field("last_run_at", .datetime)
            .field("next_run_at", .datetime, .required)
            .create()
    }
    func revert(on database: Database) async throws {
        try await database.schema("scheduled_scans").delete()
    }
}
