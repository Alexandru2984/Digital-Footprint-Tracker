import Crypto
import Foundation
import Vapor

/// Shared helpers for at-rest field encryption + blind indexing.
///
/// `encrypt`/`decrypt` wrap `TokenEncryption` (AES-256-GCM) with the same
/// fail-open-to-plaintext + legacy-plaintext-fallback behaviour used across the
/// app. `blindIndex` is a deterministic keyed hash (HMAC-SHA256) that lets an
/// encrypted column still be looked up by equality: two identical plaintexts map
/// to the same index, but the index reveals nothing without `ENCRYPTION_KEY`
/// (unlike a bare SHA-256, which is dictionary-attackable for low-entropy values
/// like emails or usernames).
enum FieldCrypto {
    static func encrypt(_ plaintext: String) -> String {
        guard TokenEncryption.isAvailable() else { return plaintext }
        return (try? TokenEncryption.encrypt(plaintext)) ?? plaintext
    }

    static func decrypt(_ stored: String) -> String? {
        TokenEncryption.decrypt(stored)
    }

    /// Deterministic keyed hash of `value` for equality lookups on an encrypted
    /// column. Falls back to plain SHA-256 when no key is configured (dedup still
    /// works; it's just not blinded).
    static func blindIndex(_ value: String) -> String {
        let msg = Data(value.utf8)
        if let key = keyBytes() {
            let mac = HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key))
            return mac.map { String(format: "%02x", $0) }.joined()
        }
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
