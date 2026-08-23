import Crypto
import Foundation
import Vapor

/// AES-256-GCM encryption helper for sensitive fields stored in the database.
/// Key is loaded from the ENCRYPTION_KEY environment variable (64 hex chars = 32 bytes).
///
/// Usage:
///   - Encrypt before saving:  `TokenEncryption.encrypt(plaintext)`
///   - Decrypt before using:   `TokenEncryption.decrypt(ciphertext)`
/// New ciphertexts carry an `enc:v1:` prefix. This makes a key mismatch or damaged
/// ciphertext distinguishable from a legacy plaintext row instead of silently
/// returning the ciphertext as if it were user data.
enum TokenEncryption {
    enum Error: Swift.Error, CustomStringConvertible, Equatable, Sendable {
        case keyMissing, invalidKey, invalidCiphertext, decryptionFailed

        var description: String {
            switch self {
            case .keyMissing: return "ENCRYPTION_KEY is missing"
            case .invalidKey: return "ENCRYPTION_KEY must contain exactly 64 hexadecimal characters"
            case .invalidCiphertext: return "encrypted field has an invalid format"
            case .decryptionFailed: return "encrypted field could not be decrypted with the configured key"
            }
        }
    }

    private static let envelopePrefix = "enc:v1:"

    static func isConfigured() -> Bool {
        guard let value = Environment.get("ENCRYPTION_KEY") else { return false }
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static func isAvailable() -> Bool { (try? symmetricKey()) != nil }

    /// Validate configuration at startup. Production calls this with `required`
    /// so sensitive writes can never silently fall back to plaintext.
    static func validateConfiguration(required: Bool) throws {
        if !isConfigured() {
            if required { throw Error.keyMissing }
            return
        }
        _ = try symmetricKey()
    }

    private static func symmetricKey() throws -> SymmetricKey {
        guard let raw = Environment.get("ENCRYPTION_KEY") else { throw Error.keyMissing }
        let hex = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count == 64 else { throw Error.invalidKey }
        var bytes: [UInt8] = []
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            guard let byte = UInt8(hex[idx..<next], radix: 16) else { throw Error.invalidKey }
            bytes.append(byte)
            idx = next
        }
        guard bytes.count == 32 else { throw Error.invalidKey }
        return SymmetricKey(data: bytes)
    }

    /// Encrypt a plaintext string. Returns base64-encoded nonce+ciphertext+tag.
    static func encrypt(_ plaintext: String) throws -> String {
        let key = try symmetricKey()
        let box = try AES.GCM.seal(Data(plaintext.utf8), using: key)
        guard let combined = box.combined else { throw Error.decryptionFailed }
        return envelopePrefix + combined.base64EncodedString()
    }

    /// Decrypt a tagged ciphertext or an untagged legacy ciphertext. Returning nil
    /// is reserved for legacy plaintext detection; tagged ciphertext is handled by
    /// `FieldCrypto.decryptStored`, which fails closed when it cannot be opened.
    static func decrypt(_ ciphertext: String) -> String? {
        try? decryptRequired(ciphertext)
    }

    static func isEncryptedEnvelope(_ value: String) -> Bool {
        value.hasPrefix(envelopePrefix)
    }

    static func decryptRequired(_ ciphertext: String) throws -> String {
        let encoded = ciphertext.hasPrefix(envelopePrefix)
            ? String(ciphertext.dropFirst(envelopePrefix.count))
            : ciphertext
        guard let data = Data(base64Encoded: encoded),
              let box = try? AES.GCM.SealedBox(combined: data)
        else { throw Error.invalidCiphertext }
        let key = try symmetricKey()
        let plain: Data
        do {
            plain = try AES.GCM.open(box, using: key)
        } catch {
            throw Error.decryptionFailed
        }
        guard let str = String(data: plain, encoding: .utf8) else {
            throw Error.invalidCiphertext
        }
        return str
    }
}
