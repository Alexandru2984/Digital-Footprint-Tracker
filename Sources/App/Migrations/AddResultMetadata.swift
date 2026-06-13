import Fluent

/// Adds an optional `metadata` column to `results` for structured, machine-readable
/// finding data (JSON), alongside the human-readable `raw_data` string.
///
/// Uses the Fluent schema builder rather than raw SQL so it is dialect-neutral
/// (PostgreSQL in prod, SQLite in tests). Nullable + additive: existing rows and
/// plugins that don't populate it are unaffected.
struct AddResultMetadata: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("results")
            .field("metadata", .string)
            .update()
    }

    func revert(on database: Database) async throws {
        try await database.schema("results")
            .deleteField("metadata")
            .update()
    }
}
