import Fluent

/// One-time rewrite of legacy plaintext and unversioned ciphertext into the
/// versioned AES-GCM envelope used by `FieldCrypto`.
///
/// The production startup validates ENCRYPTION_KEY before migrations run. Local
/// test/development environments without a key intentionally skip this rewrite.
/// Cache rows are disposable and are purged instead of rewritten so both their
/// payload encryption and their HMAC target keys start in a consistent state.
struct MigrateSensitiveFieldEncryption: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard TokenEncryption.isAvailable() else { return }
        try await EncryptionKeyVerifier.verifyOrInitialize(on: database)

        for result in try await Result.query(on: database).all() {
            result.setRawData(try result.rawData)
            result.setMetadata(try result.metadata)
            try await result.save(on: database)
        }

        for scan in try await Scan.query(on: database).all() {
            scan.setInput(try scan.input)
            try await scan.save(on: database)
        }

        for board in try await Investigation.query(on: database).all() {
            board.setName(try board.name)
            board.setData(try board.data)
            try await board.save(on: database)
        }

        for user in try await User.query(on: database).all() {
            user.setWebhookURL(try user.webhookURL)
            user.setDiscordWebhookURL(try user.discordWebhookURL)
            user.setTelegramBotToken(try user.telegramBotToken)
            user.setTelegramChatID(try user.telegramChatID)
            user.setSlackWebhookURL(try user.slackWebhookURL)
            user.setTOTPSecret(try user.totpSecret)
            try await user.save(on: database)
        }

        for schedule in try await ScheduledScan.query(on: database).all() {
            schedule.setInput(try schedule.input)
            try await schedule.save(on: database)
        }

        for notification in try await ScanNotification.query(on: database).all() {
            notification.setMessage(try notification.message)
            try await notification.save(on: database)
        }

        for tag in try await Tag.query(on: database).all() {
            tag.setName(try tag.name)
            try await tag.save(on: database)
        }

        for entry in try await AuditLog.query(on: database).all() {
            entry.setTarget(try entry.target)
            entry.setIP(try entry.ip)
            try await entry.save(on: database)
        }

        try await PluginCacheEntry.query(on: database).delete()
    }

    /// Encryption is intentionally not reversed: reverting to plaintext would be
    /// a security regression and old application versions can still read legacy
    /// unprefixed AES-GCM values after a controlled rollback.
    func revert(on database: Database) async throws {}
}
