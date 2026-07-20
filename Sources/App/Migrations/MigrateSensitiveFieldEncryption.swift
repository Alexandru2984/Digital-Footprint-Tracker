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
            result.rawData = result.rawData
            result.metadata = result.metadata
            try await result.save(on: database)
        }

        for scan in try await Scan.query(on: database).all() {
            scan.input = scan.input
            try await scan.save(on: database)
        }

        for board in try await Investigation.query(on: database).all() {
            board.name = board.name
            board.data = board.data
            try await board.save(on: database)
        }

        for user in try await User.query(on: database).all() {
            user.webhookURL = user.webhookURL
            user.discordWebhookURL = user.discordWebhookURL
            user.telegramBotToken = user.telegramBotToken
            user.telegramChatID = user.telegramChatID
            user.slackWebhookURL = user.slackWebhookURL
            user.totpSecret = user.totpSecret
            try await user.save(on: database)
        }

        for schedule in try await ScheduledScan.query(on: database).all() {
            schedule.input = schedule.input
            try await schedule.save(on: database)
        }

        for notification in try await ScanNotification.query(on: database).all() {
            notification.message = notification.message
            try await notification.save(on: database)
        }

        for entry in try await AuditLog.query(on: database).all() {
            entry.target = entry.target
            entry.ip = entry.ip
            try await entry.save(on: database)
        }

        try await PluginCacheEntry.query(on: database).delete()
    }

    /// Encryption is intentionally not reversed: reverting to plaintext would be
    /// a security regression and old application versions can still read legacy
    /// unprefixed AES-GCM values after a controlled rollback.
    func revert(on database: Database) async throws {}
}
