import Fluent

struct CreateScan: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("scans")
            .id()
            .field("input", .string, .required)
            .field("created_at", .datetime)
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("scans").delete()
    }
}
