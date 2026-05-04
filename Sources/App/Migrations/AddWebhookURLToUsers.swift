import Fluent

struct AddWebhookURLToUsers: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("users")
            .field("webhook_url", .string)
            .update()
    }
    func revert(on database: Database) async throws {
        try await database.schema("users")
            .deleteField("webhook_url")
            .update()
    }
}
