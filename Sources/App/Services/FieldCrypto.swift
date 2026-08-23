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
    /// Fixed identifiers keep metrics cardinality bounded and identify the
    /// exact data class without ever logging ciphertext or plaintext.
    enum StoredField: String, CaseIterable, Hashable, Sendable {
        case scanInput = "scans.input"
        case resultRawData = "results.raw_data"
        case resultMetadata = "results.metadata"
        case scheduledScanInput = "scheduled_scans.input"
        case investigationName = "investigations.name"
        case investigationData = "investigations.data"
        case darkWebTarget = "dark_web_investigations.target"
        case darkWebResult = "dark_web_investigations.result"
        case notificationMessage = "scan_notifications.message"
        case auditTarget = "audit_logs.target"
        case auditIP = "audit_logs.ip"
        case tagName = "tags.name"
        case userWebhookURL = "users.webhook_url"
        case userDiscordWebhookURL = "users.discord_webhook_url"
        case userTelegramBotToken = "users.telegram_bot_token"
        case userTelegramChatID = "users.telegram_chat_id"
        case userSlackWebhookURL = "users.slack_webhook_url"
        case userTOTPSecret = "users.totp_secret"
    }

    enum DecryptionReason: String, CaseIterable, Hashable, Sendable {
        case invalidEnvelope = "invalid_envelope"
        case keyUnavailable = "key_unavailable"
        case authenticationFailed = "authentication_failed"
    }

    struct DecryptionFailure: Swift.Error, Sendable {
        let field: StoredField
        let recordID: UUID?
        let reason: DecryptionReason
    }

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

    /// Plaintext view for model accessors. Legacy plaintext remains readable.
    /// A tagged value that cannot be authenticated throws a typed error so a
    /// request can fail safely or a background job can quarantine the record;
    /// corrupted database data must never terminate the process.
    static func decryptStored(
        _ stored: String,
        field: StoredField,
        recordID: UUID? = nil
    ) throws -> String {
        if TokenEncryption.isEncryptedEnvelope(stored) {
            do {
                return try TokenEncryption.decryptRequired(stored)
            } catch let error as TokenEncryption.Error {
                let reason: DecryptionReason
                switch error {
                case .invalidCiphertext:
                    reason = .invalidEnvelope
                case .keyMissing, .invalidKey:
                    reason = .keyUnavailable
                case .decryptionFailed:
                    reason = .authenticationFailed
                }
                throw DecryptionFailure(field: field, recordID: recordID, reason: reason)
            } catch {
                throw DecryptionFailure(
                    field: field, recordID: recordID, reason: .authenticationFailed
                )
            }
        }
        if let plaintext = TokenEncryption.decrypt(stored) { return plaintext }
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
