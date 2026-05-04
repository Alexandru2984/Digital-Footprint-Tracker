import Fluent
struct CreateAuditLogs: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("audit_logs")
            .id()
            .field("user_id", .uuid)
            .field("action", .string, .required)
            .field("target", .string, .required)
            .field("ip", .string, .required)
            .field("created_at", .datetime)
            .create()
    }
    func revert(on database: Database) async throws {
        try await database.schema("audit_logs").delete()
    }
}
