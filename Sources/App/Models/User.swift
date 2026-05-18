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

    /// Opt-in: when true, the user receives a notification for every completed
    /// scheduled scan. When false (default), they're only notified when monitor
    /// mode detects net-new findings.
    @Field(key: "verbose_alerts")
    var verboseAlerts: Bool

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Children(for: \.$user)
    var scans: [Scan]

    init() { }

    init(id: UUID? = nil, username: String, email: String, passwordHash: String, isAdmin: Bool = false, webhookURL: String? = nil, retentionDays: Int? = nil, discordWebhookURL: String? = nil, telegramBotToken: String? = nil, telegramChatID: String? = nil, slackWebhookURL: String? = nil, verboseAlerts: Bool = false) {
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
        self.verboseAlerts = verboseAlerts
    }
}

extension User {
    /// Public representation — never includes secrets (password hash, tokens, webhook URLs).
    /// Sensitive channels are exposed only as boolean "configured" flags.
    struct Public: Content {
        let id: UUID?
        let username: String
        let email: String
        let isAdmin: Bool
        let retentionDays: Int?
        let createdAt: Date?
        // Webhook URL: masked to avoid leaking the full URL (may contain secrets/tokens)
        let webhookURL: String?
        // Boolean flags so the UI can show "configured" without leaking credentials
        let discordConfigured: Bool
        let telegramConfigured: Bool
        let slackConfigured: Bool
        // Chat ID is not a secret (just a numeric ID), safe to return
        let telegramChatID: String?
        let verboseAlerts: Bool
    }

    func toPublic() -> Public {
        Public(
            id: id,
            username: username,
            email: email,
            isAdmin: isAdmin,
            retentionDays: retentionDays,
            createdAt: createdAt,
            webhookURL: webhookURL.map { maskSecret($0) },
            discordConfigured: discordWebhookURL != nil,
            telegramConfigured: telegramBotToken != nil,
            slackConfigured: slackWebhookURL != nil,
            telegramChatID: telegramChatID,
            verboseAlerts: verboseAlerts
        )
    }
}

/// Returns the first 12 characters of a secret followed by asterisks.
private func maskSecret(_ s: String) -> String {
    guard s.count > 12 else { return String(repeating: "*", count: s.count) }
    return String(s.prefix(12)) + "***"
}
