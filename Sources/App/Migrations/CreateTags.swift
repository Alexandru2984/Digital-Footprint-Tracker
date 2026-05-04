import Fluent
struct CreateTags: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("tags")
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("name", .string, .required)
            .field("colour", .string, .required)
            .create()
    }
    func revert(on database: Database) async throws {
        try await database.schema("tags").delete()
    }
}
