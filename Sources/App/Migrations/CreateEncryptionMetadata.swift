import Fluent

struct CreateEncryptionMetadata: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema(EncryptionMetadata.schema)
            .id()
            .field("name", .string, .required)
            .field("value", .string, .required)
            .unique(on: "name")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema(EncryptionMetadata.schema).delete()
    }
}
