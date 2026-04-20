import Fluent

struct CreateResult: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("results")
            .id()
            .field("scan_id", .uuid, .required, .references("scans", "id", onDelete: .cascade))
            .field("source", .string, .required)
            .field("type", .string, .required)
            .field("confidence_score", .double, .required)
            .field("raw_data", .string, .required)
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("results").delete()
    }
}
