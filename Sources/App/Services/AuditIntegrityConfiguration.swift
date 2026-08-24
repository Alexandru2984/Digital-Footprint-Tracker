import Crypto
import Foundation
import Vapor

struct AuditIntegrityConfiguration: Sendable {
    enum ConfigurationError: Error, CustomStringConvertible, Equatable {
        case missingKey
        case incompleteConfiguration
        case invalidKey
        case invalidKeyID
        case missingCommitmentKey
        case invalidCommitmentKey
        case reusedKeyMaterial

        var description: String {
            switch self {
            case .missingKey:
                return "AUDIT_SIGNING_KEY is required in production"
            case .incompleteConfiguration:
                return "AUDIT_SIGNING_KEY and AUDIT_SIGNING_KEY_ID must be configured together"
            case .invalidKey:
                return "AUDIT_SIGNING_KEY must contain exactly 64 hexadecimal characters"
            case .invalidKeyID:
                return "AUDIT_SIGNING_KEY_ID must match [A-Za-z0-9][A-Za-z0-9._-]{0,31}"
            case .missingCommitmentKey:
                return "AUDIT_COMMITMENT_KEY is required whenever signed audit integrity is enabled"
            case .invalidCommitmentKey:
                return "AUDIT_COMMITMENT_KEY must contain exactly 64 hexadecimal characters"
            case .reusedKeyMaterial:
                return "audit signing, audit commitment and encryption keys must be independent"
            }
        }
    }

    let keyID: String
    private let privateKeyBytes: Data
    private let commitmentKeyBytes: Data
    let publicKeyBytes: Data

    init(keyID: String, privateKeyHex: String, commitmentKeyHex: String) throws {
        let normalizedID = keyID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalizedID.range(
            of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$",
            options: .regularExpression
        ) != nil else {
            throw ConfigurationError.invalidKeyID
        }
        let keyData = try Self.parseHexKey(privateKeyHex)
        let signer: Curve25519.Signing.PrivateKey
        do {
            signer = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
        } catch {
            throw ConfigurationError.invalidKey
        }
        let commitmentKeyData: Data
        do {
            commitmentKeyData = try Self.parseHexKey(commitmentKeyHex)
        } catch {
            throw ConfigurationError.invalidCommitmentKey
        }
        guard commitmentKeyData != keyData else {
            throw ConfigurationError.reusedKeyMaterial
        }
        self.keyID = normalizedID
        self.privateKeyBytes = keyData
        self.commitmentKeyBytes = commitmentKeyData
        self.publicKeyBytes = signer.publicKey.rawRepresentation
    }

    static func fromEnvironment(required: Bool) throws -> AuditIntegrityConfiguration? {
        let rawKey = Environment.get("AUDIT_SIGNING_KEY")?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let rawID = Environment.get("AUDIT_SIGNING_KEY_ID")?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let rawCommitmentKey = Environment.get("AUDIT_COMMITMENT_KEY")?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if rawKey.isEmpty && rawID.isEmpty && rawCommitmentKey.isEmpty {
            if required { throw ConfigurationError.missingKey }
            return nil
        }
        guard !rawKey.isEmpty, !rawID.isEmpty else {
            throw ConfigurationError.incompleteConfiguration
        }
        guard !rawCommitmentKey.isEmpty else {
            throw ConfigurationError.missingCommitmentKey
        }
        let configuration = try AuditIntegrityConfiguration(
            keyID: rawID,
            privateKeyHex: rawKey,
            commitmentKeyHex: rawCommitmentKey
        )
        let encryptionKey = Environment.get("ENCRYPTION_KEY")?
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        if !encryptionKey.isEmpty,
           encryptionKey == rawKey.lowercased() || encryptionKey == rawCommitmentKey.lowercased() {
            throw ConfigurationError.reusedKeyMaterial
        }
        return configuration
    }

    func sign(_ data: Data) throws -> Data {
        try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
            .signature(for: data)
    }

    func commit(_ data: Data) -> String {
        HMAC<SHA256>.authenticationCode(
            for: data,
            using: SymmetricKey(data: commitmentKeyBytes)
        ).map { String(format: "%02x", $0) }.joined()
    }

    private static func parseHexKey(_ raw: String) throws -> Data {
        let hex = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count == 64 else { throw ConfigurationError.invalidKey }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                throw ConfigurationError.invalidKey
            }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }
}

private struct AuditIntegrityConfigurationKey: StorageKey {
    typealias Value = AuditIntegrityConfiguration
}

extension Application {
    var auditIntegrityConfiguration: AuditIntegrityConfiguration? {
        get { storage[AuditIntegrityConfigurationKey.self] }
        set { storage[AuditIntegrityConfigurationKey.self] = newValue }
    }
}
