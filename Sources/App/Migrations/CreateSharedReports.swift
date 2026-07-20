import Fluent

struct CreateSharedReports: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("shared_reports")
            .id()
            .field("scan_id", .uuid, .required, .references("scans", "id", onDelete: .cascade))
            // Fresh databases start on the final hash-only schema. Existing
            // installations are upgraded by HashSharedReportTokens.
            .field("token_hash", .string, .required)
            .field("expires_at", .datetime)
            .field("password_hash", .string)
            .field("view_count", .int, .required)
            .field("created_at", .datetime)
            .unique(on: "token_hash")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("shared_reports").delete()
    }
}
