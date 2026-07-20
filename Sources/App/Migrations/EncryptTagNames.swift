import Fluent

/// Encrypts tag labels created before tag names joined the sensitive-field set.
struct EncryptTagNames: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard TokenEncryption.isAvailable() else { return }
        for tag in try await Tag.query(on: database).all()
            where !TokenEncryption.isEncryptedEnvelope(tag.nameCipher) {
            tag.name = tag.name
            try await tag.save(on: database)
        }
    }

    func revert(on database: Database) async throws {
        // Encryption is intentionally one-way at the schema lifecycle level.
    }
}
