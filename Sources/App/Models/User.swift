import Fluent
import Vapor

final class User: Model, Content {
    static let schema = "users"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "username")
    var username: String

    @Field(key: "email")
    var email: String

    @Field(key: "password_hash")
    var passwordHash: String

    @Field(key: "is_admin")
    var isAdmin: Bool

    @OptionalField(key: "webhook_url")
    var webhookURL: String?

    @OptionalField(key: "retention_days")
    var retentionDays: Int?

    @OptionalField(key: "discord_webhook_url")
    var discordWebhookURL: String?

    @OptionalField(key: "telegram_bot_token")
    var telegramBotToken: String?

    @OptionalField(key: "telegram_chat_id")
    var telegramChatID: String?

    @OptionalField(key: "slack_webhook_url")
    var slackWebhookURL: String?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Children(for: \.$user)
    var scans: [Scan]

    init() { }

    init(id: UUID? = nil, username: String, email: String, passwordHash: String, isAdmin: Bool = false, webhookURL: String? = nil, retentionDays: Int? = nil, discordWebhookURL: String? = nil, telegramBotToken: String? = nil, telegramChatID: String? = nil, slackWebhookURL: String? = nil) {
        self.id = id
        self.username = username
        self.email = email
        self.passwordHash = passwordHash
        self.isAdmin = isAdmin
        self.webhookURL = webhookURL
        self.retentionDays = retentionDays
        self.discordWebhookURL = discordWebhookURL
        self.telegramBotToken = telegramBotToken
        self.telegramChatID = telegramChatID
        self.slackWebhookURL = slackWebhookURL
    }
}

extension User {
    /// Public representation — never includes the password hash.
    struct Public: Content {
        let id: UUID?
        let username: String
        let email: String
        let isAdmin: Bool
        let webhookURL: String?
        let retentionDays: Int?
        let createdAt: Date?
        let discordWebhookURL: String?
        let telegramBotToken: String?
        let telegramChatID: String?
        let slackWebhookURL: String?
    }

    func toPublic() -> Public {
        Public(id: id, username: username, email: email, isAdmin: isAdmin, webhookURL: webhookURL, retentionDays: retentionDays, createdAt: createdAt, discordWebhookURL: discordWebhookURL, telegramBotToken: telegramBotToken, telegramChatID: telegramChatID, slackWebhookURL: slackWebhookURL)
    }
}
