import Fluent

struct AddUserIDToScans: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("scans")
            .field("user_id", .uuid, .references("users", "id", onDelete: .setNull))
            .update()
    }

    func revert(on database: Database) async throws {
        try await database.schema("scans")
            .deleteField("user_id")
            .update()
    }
}
