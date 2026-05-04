import Fluent

struct AddNotificationChannelsToUsers: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("users").field("discord_webhook_url", .string).update()
        try await database.schema("users").field("telegram_bot_token", .string).update()
        try await database.schema("users").field("telegram_chat_id", .string).update()
        try await database.schema("users").field("slack_webhook_url", .string).update()
    }

    func revert(on database: Database) async throws {
        try await database.schema("users").deleteField("discord_webhook_url").update()
        try await database.schema("users").deleteField("telegram_bot_token").update()
        try await database.schema("users").deleteField("telegram_chat_id").update()
        try await database.schema("users").deleteField("slack_webhook_url").update()
    }
}
