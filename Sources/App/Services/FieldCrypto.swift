import Crypto
import Foundation
import Vapor

/// Shared helpers for at-rest field encryption + blind indexing.
///
/// `encrypt`/`decryptStored` wrap `TokenEncryption` (AES-256-GCM). Development
/// may intentionally run without a key, but a configured-yet-invalid key never
/// falls back to plaintext. `blindIndex` is a deterministic keyed hash
/// (HMAC-SHA256) that lets an
/// encrypted column still be looked up by equality: two identical plaintexts map
/// to the same index, but the index reveals nothing without `ENCRYPTION_KEY`
/// (unlike a bare SHA-256, which is dictionary-attackable for low-entropy values
/// like emails or usernames).
enum FieldCrypto {
    static func encrypt(_ plaintext: String) -> String {
        guard TokenEncryption.isConfigured() else { return plaintext }
        do {
            return try TokenEncryption.encrypt(plaintext)
        } catch {
            // Model computed setters cannot throw. Crashing before persistence is
            // preferable to silently storing a secret in cleartext; production
            // validates this key during startup, so this only catches runtime
            // configuration corruption.
            preconditionFailure("Sensitive-field encryption failed: \(error)")
        }
    }

    static func decrypt(_ stored: String) -> String? {
        TokenEncryption.decrypt(stored)
    }

    /// Plaintext view for model accessors. Legacy plaintext remains readable,
    /// while a tagged value that cannot be decrypted fails closed instead of
    /// leaking ciphertext through APIs or being re-saved as plaintext.
    static func decryptStored(_ stored: String) -> String {
        if let plaintext = TokenEncryption.decrypt(stored) { return plaintext }
        guard !TokenEncryption.isEncryptedEnvelope(stored) else {
            preconditionFailure("Encrypted field cannot be decrypted with the configured key")
        }
        return stored
    }

    /// Deterministic keyed hash of `value` for equality lookups on an encrypted
    /// column. Falls back to plain SHA-256 only when no key is configured (local
    /// development); a malformed configured key fails closed.
    static func blindIndex(_ value: String) -> String {
        let msg = Data(value.utf8)
        if let key = keyBytes() {
            let mac = HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key))
            return mac.map { String(format: "%02x", $0) }.joined()
        }
        precondition(!TokenEncryption.isConfigured(), "ENCRYPTION_KEY is configured but invalid")
        return SHA256.hash(data: msg).map { String(format: "%02x", $0) }.joined()
    }

    /// Parse the 64-hex-char ENCRYPTION_KEY into 32 bytes (nil if absent/malformed).
    private static func keyBytes() -> [UInt8]? {
        guard let hex = Environment.get("ENCRYPTION_KEY") else { return nil }
        var bytes: [UInt8] = []
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            guard let byte = UInt8(hex[idx..<next], radix: 16) else { return nil }
            bytes.append(byte)
            idx = next
        }
        return bytes.count == 32 ? bytes : nil
    }
}
