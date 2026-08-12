import Fluent
import Vapor

final class User: Model {
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
    var webhookURLCipher: String?
    var webhookURL: String? {
        get { webhookURLCipher.map(FieldCrypto.decryptStored) }
        set { webhookURLCipher = newValue.map(FieldCrypto.encrypt) }
    }

    @OptionalField(key: "retention_days")
    var retentionDays: Int?

    @OptionalField(key: "discord_webhook_url")
    var discordWebhookURLCipher: String?
    var discordWebhookURL: String? {
        get { discordWebhookURLCipher.map(FieldCrypto.decryptStored) }
        set { discordWebhookURLCipher = newValue.map(FieldCrypto.encrypt) }
    }

    @OptionalField(key: "telegram_bot_token")
    var telegramBotTokenCipher: String?
    var telegramBotToken: String? {
        get { telegramBotTokenCipher.map(FieldCrypto.decryptStored) }
        set { telegramBotTokenCipher = newValue.map(FieldCrypto.encrypt) }
    }

    @OptionalField(key: "telegram_chat_id")
    var telegramChatIDCipher: String?
    var telegramChatID: String? {
        get { telegramChatIDCipher.map(FieldCrypto.decryptStored) }
        set { telegramChatIDCipher = newValue.map(FieldCrypto.encrypt) }
    }

    @OptionalField(key: "slack_webhook_url")
    var slackWebhookURLCipher: String?
    var slackWebhookURL: String? {
        get { slackWebhookURLCipher.map(FieldCrypto.decryptStored) }
        set { slackWebhookURLCipher = newValue.map(FieldCrypto.encrypt) }
    }

    /// Opt-in: when true, the user receives a notification for every completed
    /// scheduled scan. When false (default), they're only notified when monitor
    /// mode detects net-new findings.
    @Field(key: "verbose_alerts")
    var verboseAlerts: Bool

    // ── Two-factor authentication (TOTP) ──────────────────────────────────
    /// Base32 TOTP secret, encrypted at rest (see `TokenEncryption`). Set during
    /// setup; `totpEnabled` stays false until the user proves possession.
    @OptionalField(key: "totp_secret")
    var totpSecretCipher: String?
    var totpSecret: String? {
        get { totpSecretCipher.map(FieldCrypto.decryptStored) }
        set { totpSecretCipher = newValue.map(FieldCrypto.encrypt) }
    }

    @Field(key: "totp_enabled")
    var totpEnabled: Bool

    /// JSON array of SHA-256-hashed one-time recovery codes. Consumed on use.
    @OptionalField(key: "totp_recovery_codes")
    var totpRecoveryCodes: String?

    /// Last accepted TOTP time-step. A code at or below this step is a replay and
    /// is rejected (RFC 6238 §5.2). Nil until the first code is accepted.
    @OptionalField(key: "last_totp_step")
    var lastTotpStep: Int?

    // ── Email verification ────────────────────────────────────────────────
    @Field(key: "email_verified")
    var emailVerified: Bool

    /// SHA-256 hash of the pending verification token (raw token only in the email).
    @OptionalField(key: "email_verification_token")
    var emailVerificationToken: String?

    @OptionalField(key: "email_verification_expires")
    var emailVerificationExpires: Date?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Children(for: \.$user)
    var scans: [Scan]

    init() { }

    init(id: UUID? = nil, username: String, email: String, passwordHash: String, isAdmin: Bool = false, webhookURL: String? = nil, retentionDays: Int? = 30, discordWebhookURL: String? = nil, telegramBotToken: String? = nil, telegramChatID: String? = nil, slackWebhookURL: String? = nil, verboseAlerts: Bool = false, emailVerified: Bool = false) {
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
        self.totpEnabled = false
        self.emailVerified = emailVerified
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
        let twoFactorEnabled: Bool
        let emailVerified: Bool
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
            verboseAlerts: verboseAlerts,
            twoFactorEnabled: totpEnabled,
            emailVerified: emailVerified
        )
    }
}

/// Returns the first 12 characters of a secret followed by asterisks.
private func maskSecret(_ s: String) -> String {
    guard s.count > 12 else { return String(repeating: "*", count: s.count) }
    return String(s.prefix(12)) + "***"
}
