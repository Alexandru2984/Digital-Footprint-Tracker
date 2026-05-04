import Fluent

struct CreateSharedReports: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("shared_reports")
            .id()
            .field("scan_id", .uuid, .required)
            .field("token", .string, .required)
            .field("expires_at", .datetime)
            .field("password_hash", .string)
            .field("view_count", .int, .required)
            .field("created_at", .datetime)
            .unique(on: "token")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("shared_reports").delete()
    }
}
