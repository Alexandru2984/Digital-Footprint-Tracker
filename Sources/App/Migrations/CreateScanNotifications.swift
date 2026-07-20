import Fluent

struct CreateScanNotifications: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("scan_notifications")
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("scan_id", .uuid, .required, .references("scans", "id", onDelete: .cascade))
            .field("message", .string, .required)
            .field("new_results_count", .int, .required)
            .field("is_read", .bool, .required)
            .field("created_at", .datetime)
            .create()
    }
    func revert(on database: Database) async throws {
        try await database.schema("scan_notifications").delete()
    }
}
