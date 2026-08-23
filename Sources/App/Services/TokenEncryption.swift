import Crypto
import Foundation
import Vapor

/// Versioned AES-256-GCM encryption with a bounded keyring.
///
/// `enc:v1:<base64>` is the legacy envelope: it uses the root key directly and
/// carries no AAD or key identifier. `enc:v2:<key-id>:<base64>` derives a
/// field-encryption key with HKDF-SHA256 and authenticates the key ID, storage
/// field and row UUID. Readers accept both versions so v2 can be deployed before
/// writes or rotation are enabled.
enum TokenEncryption {
    enum Error: Swift.Error, CustomStringConvertible, Equatable, Sendable {
        case keyMissing
        case invalidKey
        case invalidKeyring
        case invalidWriteVersion
        case invalidCiphertext
        case unsupportedVersion
        case unknownKeyID
        case contextMissing
        case decryptionFailed

        var description: String {
            switch self {
            case .keyMissing:
                return "ENCRYPTION_KEY is missing"
            case .invalidKey:
                return "an encryption key must contain exactly 64 hexadecimal characters"
            case .invalidKeyring:
                return "the encryption keyring configuration is invalid"
            case .invalidWriteVersion:
                return "ENCRYPTION_WRITE_VERSION must be 1 or 2"
            case .invalidCiphertext:
                return "encrypted field has an invalid format"
            case .unsupportedVersion:
                return "encrypted field uses an unsupported envelope version"
            case .unknownKeyID:
                return "encrypted field references an unavailable key ID"
            case .contextMissing:
                return "encrypted field is missing its authenticated storage context"
            case .decryptionFailed:
                return "encrypted field could not be authenticated with an available key"
            }
        }
    }

    enum WriteVersion: String, Sendable {
        case v1 = "1"
        case v2 = "2"
    }

    struct Context: Equatable, Sendable {
        let field: String
        let recordID: UUID
    }

    private struct KeyRecord: Sendable {
        let id: String
        let root: Data
    }

    private struct Keyring: Sendable {
        let active: KeyRecord
        let previous: [KeyRecord]

        var all: [KeyRecord] { [active] + previous }
    }

    private static let v1Prefix = "enc:v1:"
    private static let v2Prefix = "enc:v2:"
    private static let reservedPrefix = "enc:"
    private static let defaultKeyID = "primary"
    private static let maxPreviousKeys = 4
    private static let keyIDPattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$"
    private static let hkdfSalt = Data("swift-vapor/field-crypto/v2".utf8)

    static func isConfigured() -> Bool {
        guard let value = Environment.get("ENCRYPTION_KEY") else { return false }
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static func isAvailable() -> Bool { (try? keyring()) != nil }

    static func configuredWriteVersion() throws -> WriteVersion {
        let raw = Environment.get("ENCRYPTION_WRITE_VERSION")?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? WriteVersion.v1.rawValue
        guard let version = WriteVersion(rawValue: raw) else {
            throw Error.invalidWriteVersion
        }
        return version
    }

    static func activeKeyID() throws -> String { try keyring().active.id }

    /// Validate every keyring component at startup. Production requires an
    /// active root key; development may intentionally run without encryption.
    static func validateConfiguration(required: Bool) throws {
        _ = try configuredWriteVersion()
        guard isConfigured() else {
            let hasPartialKeyring = ["ENCRYPTION_KEY_ID", "ENCRYPTION_PREVIOUS_KEYS"]
                .contains { !(Environment.get($0) ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            if required || hasPartialKeyring { throw Error.keyMissing }
            return
        }
        _ = try keyring()
    }

    /// Legacy helper retained for key-check/backward-compatibility tests. New
    /// sensitive fields must call the context-bearing overload below.
    static func encrypt(_ plaintext: String) throws -> String {
        try encryptV1(plaintext, key: keyring().active)
    }

    /// Encrypt according to the explicitly configured rollout version.
    static func encrypt(_ plaintext: String, context: Context) throws -> String {
        let ring = try keyring()
        switch try configuredWriteVersion() {
        case .v1:
            return try encryptV1(plaintext, key: ring.active)
        case .v2:
            return try encryptV2(plaintext, key: ring.active, context: context)
        }
    }

    /// Context-free reads are intentionally limited to v1. V2 cannot be opened
    /// safely unless the caller supplies the row and field that were authenticated.
    static func decrypt(_ ciphertext: String) -> String? {
        try? decryptRequired(ciphertext)
    }

    static func decryptRequired(_ ciphertext: String) throws -> String {
        if ciphertext.hasPrefix(v2Prefix) { throw Error.contextMissing }
        return try decryptV1(ciphertext, keys: keyring().all)
    }

    static func decryptRequired(_ ciphertext: String, context: Context) throws -> String {
        if ciphertext.hasPrefix(v2Prefix) {
            return try decryptV2(ciphertext, ring: keyring(), context: context)
        }
        if ciphertext.hasPrefix(reservedPrefix), !ciphertext.hasPrefix(v1Prefix) {
            throw Error.unsupportedVersion
        }
        return try decryptV1(ciphertext, keys: keyring().all)
    }

    /// `enc:` is a reserved namespace. Treating an unknown version as plaintext
    /// would leak a tampered ciphertext through an API response.
    static func isEncryptedEnvelope(_ value: String) -> Bool {
        value.hasPrefix(reservedPrefix)
    }

    static func envelopeVersion(_ value: String) -> WriteVersion? {
        if value.hasPrefix(v1Prefix) { return .v1 }
        if value.hasPrefix(v2Prefix) { return .v2 }
        return nil
    }

    static func envelopeKeyID(_ value: String) -> String? {
        guard value.hasPrefix(v2Prefix) else { return nil }
        let parts = value.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        return String(parts[2])
    }

    static func isCurrentEnvelope(_ value: String) -> Bool {
        guard let version = try? configuredWriteVersion() else { return false }
        switch version {
        case .v1:
            return value.hasPrefix(v1Prefix)
        case .v2:
            guard let activeID = try? activeKeyID() else { return false }
            return envelopeKeyID(value) == activeID
        }
    }

    /// Active write-format blind index. V1 uses the historical raw-root HMAC;
    /// v2 derives a separate HKDF key so encryption and equality indexes never
    /// share key material.
    static func blindIndex(_ value: String) throws -> String {
        let ring = try keyring()
        switch try configuredWriteVersion() {
        case .v1:
            return hmacHex(value, key: SymmetricKey(data: ring.active.root))
        case .v2:
            return hmacHex(value, key: derivedKey(for: ring.active, purpose: "blind-index"))
        }
    }

    /// All active/previous v2 and legacy hashes. Querying this bounded set keeps
    /// equality lookups working while rows are re-indexed online.
    static func blindIndexCandidates(_ value: String) throws -> [String] {
        let ring = try keyring()
        var seen = Set<String>()
        var candidates: [String] = []
        for key in ring.all {
            let v2 = hmacHex(value, key: derivedKey(for: key, purpose: "blind-index"))
            if seen.insert(v2).inserted { candidates.append(v2) }
            let legacy = hmacHex(value, key: SymmetricKey(data: key.root))
            if seen.insert(legacy).inserted { candidates.append(legacy) }
        }
        return candidates
    }

    private static func encryptV1(_ plaintext: String, key: KeyRecord) throws -> String {
        let box = try AES.GCM.seal(Data(plaintext.utf8), using: SymmetricKey(data: key.root))
        guard let combined = box.combined else { throw Error.invalidCiphertext }
        return v1Prefix + combined.base64EncodedString()
    }

    private static func encryptV2(
        _ plaintext: String,
        key: KeyRecord,
        context: Context
    ) throws -> String {
        let aad = authenticatedData(keyID: key.id, context: context)
        let box = try AES.GCM.seal(
            Data(plaintext.utf8),
            using: derivedKey(for: key, purpose: "encryption"),
            authenticating: aad
        )
        guard let combined = box.combined else { throw Error.invalidCiphertext }
        return "\(v2Prefix)\(key.id):\(combined.base64EncodedString())"
    }

    private static func decryptV1(_ ciphertext: String, keys: [KeyRecord]) throws -> String {
        let encoded = ciphertext.hasPrefix(v1Prefix)
            ? String(ciphertext.dropFirst(v1Prefix.count))
            : ciphertext
        guard let data = Data(base64Encoded: encoded),
              let box = try? AES.GCM.SealedBox(combined: data)
        else { throw Error.invalidCiphertext }

        for key in keys {
            guard let plaintext = try? AES.GCM.open(box, using: SymmetricKey(data: key.root)) else {
                continue
            }
            guard let string = String(data: plaintext, encoding: .utf8) else {
                throw Error.invalidCiphertext
            }
            return string
        }
        throw Error.decryptionFailed
    }

    private static func decryptV2(
        _ ciphertext: String,
        ring: Keyring,
        context: Context
    ) throws -> String {
        let parts = ciphertext.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
        guard parts.count == 4, parts[0] == "enc", parts[1] == "v2" else {
            throw Error.invalidCiphertext
        }
        let keyID = String(parts[2])
        guard isValidKeyID(keyID), let key = ring.all.first(where: { $0.id == keyID }) else {
            throw Error.unknownKeyID
        }
        guard let data = Data(base64Encoded: String(parts[3])),
              let box = try? AES.GCM.SealedBox(combined: data)
        else { throw Error.invalidCiphertext }

        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                box,
                using: derivedKey(for: key, purpose: "encryption"),
                authenticating: authenticatedData(keyID: keyID, context: context)
            )
        } catch {
            throw Error.decryptionFailed
        }
        guard let string = String(data: plaintext, encoding: .utf8) else {
            throw Error.invalidCiphertext
        }
        return string
    }

    private static func authenticatedData(keyID: String, context: Context) -> Data {
        Data("swift-vapor|enc:v2|\(keyID)|\(context.field)|\(context.recordID.uuidString.lowercased())".utf8)
    }

    private static func derivedKey(for key: KeyRecord, purpose: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: key.root),
            salt: hkdfSalt,
            info: Data("\(purpose)|\(key.id)".utf8),
            outputByteCount: 32
        )
    }

    private static func hmacHex(_ value: String, key: SymmetricKey) -> String {
        HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: key)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func keyring() throws -> Keyring {
        guard let activeRaw = Environment.get("ENCRYPTION_KEY") else { throw Error.keyMissing }
        let activeID = Environment.get("ENCRYPTION_KEY_ID")?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? defaultKeyID
        guard isValidKeyID(activeID) else { throw Error.invalidKeyring }
        let active = KeyRecord(id: activeID, root: try parseKey(activeRaw))

        let rawPrevious = Environment.get("ENCRYPTION_PREVIOUS_KEYS")?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let entries = rawPrevious.isEmpty
            ? []
            : rawPrevious.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard entries.count <= maxPreviousKeys else { throw Error.invalidKeyring }

        var previous: [KeyRecord] = []
        var ids = Set([active.id])
        var keyBytes = Set([active.root])
        for entry in entries {
            let pair = entry.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2 else { throw Error.invalidKeyring }
            let id = String(pair[0]).trimmingCharacters(in: .whitespacesAndNewlines)
            let raw = String(pair[1]).trimmingCharacters(in: .whitespacesAndNewlines)
            guard isValidKeyID(id), ids.insert(id).inserted else { throw Error.invalidKeyring }
            let bytes = try parseKey(raw)
            guard keyBytes.insert(bytes).inserted else { throw Error.invalidKeyring }
            previous.append(KeyRecord(id: id, root: bytes))
        }
        return Keyring(active: active, previous: previous)
    }

    private static func isValidKeyID(_ value: String) -> Bool {
        value.range(of: keyIDPattern, options: .regularExpression) != nil
    }

    private static func parseKey(_ raw: String) throws -> Data {
        let hex = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count == 64 else { throw Error.invalidKey }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { throw Error.invalidKey }
            bytes.append(byte)
            index = next
        }
        guard bytes.count == 32 else { throw Error.invalidKey }
        return Data(bytes)
    }
}
