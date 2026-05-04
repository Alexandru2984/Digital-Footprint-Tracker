import Fluent
struct CreateScanTags: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("scan_tags")
            .id()
            .field("scan_id", .uuid, .required, .references("scans", "id", onDelete: .cascade))
            .field("tag_id",  .uuid, .required, .references("tags",  "id", onDelete: .cascade))
            .unique(on: "scan_id", "tag_id")
            .create()
    }
    func revert(on database: Database) async throws {
        try await database.schema("scan_tags").delete()
    }
}
