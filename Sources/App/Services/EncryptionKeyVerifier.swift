import Fluent

/// Persistent key-check envelope. Shape validation catches malformed keys;
/// this marker also catches a valid-looking but different key before the app
/// starts returning or rewriting encrypted data.
enum EncryptionKeyVerifier {
    private static let markerName = "master-key-check-v1"
    private static let markerPlaintext = "swift-vapor-encryption-key-check-v1"
    private static let markerField = "encryption_metadata.value"

    static func verifyOrInitialize(on database: Database) async throws {
        guard TokenEncryption.isAvailable() else { return }

        if let marker = try await EncryptionMetadata.query(on: database)
            .filter(\.$name == markerName)
            .first() {
            guard let markerID = marker.id else { throw TokenEncryption.Error.invalidCiphertext }
            let context = TokenEncryption.Context(field: markerField, recordID: markerID)
            let plaintext = try TokenEncryption.decryptRequired(marker.value, context: context)
            guard plaintext == markerPlaintext else {
                throw TokenEncryption.Error.decryptionFailed
            }
            // V1 has no key ID, so rewrite its marker under the active key on
            // every startup. V2 only needs a rewrite after the active key ID
            // changes. This makes a planned keyring rotation verifiable before
            // any application data is touched.
            if try TokenEncryption.configuredWriteVersion() == .v1
                || !TokenEncryption.isCurrentEnvelope(marker.value) {
                marker.value = try TokenEncryption.encrypt(markerPlaintext, context: context)
                try await marker.save(on: database)
            }
            return
        }

        let marker = EncryptionMetadata(name: markerName, value: "pending")
        guard let markerID = marker.id else { throw TokenEncryption.Error.invalidCiphertext }
        marker.value = try TokenEncryption.encrypt(
            markerPlaintext,
            context: .init(field: markerField, recordID: markerID)
        )
        try await marker.save(on: database)
    }
}
