import Fluent

/// Persistent key-check envelope. Shape validation catches malformed keys;
/// this marker also catches a valid-looking but different key before the app
/// starts returning or rewriting encrypted data.
enum EncryptionKeyVerifier {
    private static let markerName = "master-key-check-v1"
    private static let markerPlaintext = "swift-vapor-encryption-key-check-v1"

    static func verifyOrInitialize(on database: Database) async throws {
        guard TokenEncryption.isAvailable() else { return }

        if let marker = try await EncryptionMetadata.query(on: database)
            .filter(\.$name == markerName)
            .first() {
            let plaintext = try TokenEncryption.decryptRequired(marker.value)
            guard plaintext == markerPlaintext else {
                throw TokenEncryption.Error.decryptionFailed
            }
            return
        }

        let encrypted = try TokenEncryption.encrypt(markerPlaintext)
        try await EncryptionMetadata(name: markerName, value: encrypted).save(on: database)
    }
}
