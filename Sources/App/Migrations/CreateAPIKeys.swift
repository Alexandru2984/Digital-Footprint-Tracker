import Fluent
struct CreateAPIKeys: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("api_keys")
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("key", .string, .required)
            .field("label", .string, .required)
            .field("last_used_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "key")
            .create()
    }
    func revert(on database: Database) async throws {
        try await database.schema("api_keys").delete()
    }
}
