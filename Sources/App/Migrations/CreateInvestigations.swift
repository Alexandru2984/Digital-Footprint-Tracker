import Fluent

struct CreateInvestigations: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("investigations")
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("name", .string, .required)
            .field("data", .string, .required)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("investigations").delete()
    }
}
