import Crypto
import Foundation
import Vapor

/// AES-256-GCM encryption helper for sensitive fields stored in the database.
/// Key is loaded from the ENCRYPTION_KEY environment variable (64 hex chars = 32 bytes).
///
/// Usage:
///   - Encrypt before saving:  `TokenEncryption.encrypt(plaintext)`
///   - Decrypt before using:   `TokenEncryption.decrypt(ciphertext)`
///   - Graceful fallback:      if decrypt fails, treat stored value as plaintext (migration path)
enum TokenEncryption {
    enum Error: Swift.Error { case keyMissing, invalidKey, decryptionFailed }

    static func isAvailable() -> Bool { Environment.get("ENCRYPTION_KEY") != nil }

    private static func symmetricKey() throws -> SymmetricKey {
        guard let hex = Environment.get("ENCRYPTION_KEY") else { throw Error.keyMissing }
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
        return combined.base64EncodedString()
    }

    /// Decrypt a base64-encoded ciphertext. If decryption fails (e.g. plaintext token
    /// stored before encryption was introduced), returns nil so caller can use raw value.
    static func decrypt(_ ciphertext: String) -> String? {
        guard let key = try? symmetricKey(),
              let data = Data(base64Encoded: ciphertext),
              let box = try? AES.GCM.SealedBox(combined: data),
              let plain = try? AES.GCM.open(box, using: key),
              let str = String(data: plain, encoding: .utf8)
        else { return nil }
        return str
    }
}
