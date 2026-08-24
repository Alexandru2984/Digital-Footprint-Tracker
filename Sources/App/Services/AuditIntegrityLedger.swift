import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor

struct AuditIntegrityVerification: Content, Sendable {
    let status: String
    let failureCode: String?
    let verifiedEvents: Int
    let legacyUntrackedLogs: Int
    let lastSequence: Int64
    let headHash: String
    let activeSigningKeyID: String
    let checkedAt: Date

    var isValid: Bool { status == "valid" }
}

/// Transactional writer and full verifier for the privacy-minimal audit ledger.
enum AuditIntegrityLedger {
    static let genesisHash = String(repeating: "0", count: 64)
    static let maximumVerificationEvents = 250_000

    enum LedgerError: Error, CustomStringConvertible {
        case headMissing
        case headTailMismatch
        case sequenceExhausted
        case timestampMissing
        case invalidDigest

        var description: String {
            switch self {
            case .headMissing: return "audit integrity head is missing"
            case .headTailMismatch: return "audit integrity head does not match its immutable tail"
            case .sequenceExhausted: return "audit integrity sequence is exhausted"
            case .timestampMissing: return "audit log timestamp is missing"
            case .invalidDigest: return "audit integrity digest is malformed"
            }
        }
    }

    private struct AuditState {
        let kind: AuditIntegrityEventKind
        let payloadHash: String
    }

    private struct ChainVerification {
        let verifiedEvents: Int
        let latestState: [UUID: AuditState]
    }

    private struct VerificationIssue: Error {
        let code: String
        let verifiedEvents: Int
        let legacyLogs: Int
    }

    /// Append a signed, privacy-minimal key-transition checkpoint exactly once
    /// after first setup or signing-key rotation. The new trusted key signs the
    /// old immutable tail, so historical public keys can be retired without
    /// making earlier events replaceable by a database-only attacker.
    @discardableResult
    static func ensureActiveKeyAnchored(
        on database: Database,
        configuration: AuditIntegrityConfiguration
    ) async throws -> Bool {
        try await database.transaction { transaction in
            try await lockHead(on: transaction)
            guard let head = try await AuditIntegrityHead.find(
                AuditIntegrityHead.singletonID,
                on: transaction
            ) else {
                throw LedgerError.headMissing
            }
            if head.lastSequence == 0 {
                guard head.headHash == genesisHash else { throw LedgerError.headTailMismatch }
            } else {
                guard let tail = try await AuditIntegrityEvent.query(on: transaction)
                    .filter(\.$sequence == head.lastSequence)
                    .first(), tail.entryHash == head.headHash else {
                    throw LedgerError.headTailMismatch
                }
                if tail.signingKeyID == configuration.keyID,
                   Data(base64Encoded: tail.publicKey) == configuration.publicKeyBytes {
                    return false
                }
            }

            let target = configuration.keyID
            let ip = "[system]"
            let log = AuditLog(
                userID: nil,
                action: "audit_signing_key_activated",
                target: target,
                ip: ip
            )
            try await log.create(on: transaction)
            guard let timestamp = log.createdAt else { throw LedgerError.timestampMissing }
            let logID = try log.requireID()
            try await append(
                kind: .entry,
                auditLogID: logID,
                payloadHash: payloadHash(
                    auditLogID: logID,
                    userID: nil,
                    action: log.action,
                    target: target,
                    ip: ip,
                    recordedAt: timestamp,
                    configuration: configuration
                ),
                on: transaction,
                configuration: configuration
            )
            return true
        }
    }

    static func persist(
        _ log: AuditLog,
        plaintextTarget: String,
        plaintextIP: String,
        on database: Database,
        configuration: AuditIntegrityConfiguration
    ) async throws {
        try await database.transaction { transaction in
            try await log.create(on: transaction)
            guard let timestamp = log.createdAt else { throw LedgerError.timestampMissing }
            try await append(
                kind: .entry,
                auditLogID: try log.requireID(),
                payloadHash: payloadHash(
                    auditLogID: try log.requireID(),
                    userID: log.userID,
                    action: log.action,
                    target: plaintextTarget,
                    ip: plaintextIP,
                    recordedAt: timestamp,
                    configuration: configuration
                ),
                on: transaction,
                configuration: configuration
            )
        }
    }

    /// Record a deliberate privacy rewrite in the same transaction as the
    /// human-readable row update. The latest signed commitment is what the
    /// verifier compares with the retained display log.
    static func recordRedaction(
        of log: AuditLog,
        plaintextTarget: String,
        plaintextIP: String,
        on database: Database,
        configuration: AuditIntegrityConfiguration
    ) async throws {
        guard let timestamp = log.createdAt else { throw LedgerError.timestampMissing }
        let logID = try log.requireID()
        try await append(
            kind: .redaction,
            auditLogID: logID,
            payloadHash: payloadHash(
                auditLogID: logID,
                userID: log.userID,
                action: log.action,
                target: plaintextTarget,
                ip: plaintextIP,
                recordedAt: timestamp,
                configuration: configuration
            ),
            on: database,
            configuration: configuration
        )
    }

    /// Record an intentional retention deletion before removing the display
    /// row. No PII or deleted-row ciphertext enters the tombstone commitment.
    static func recordRetention(
        auditLogID: UUID,
        on database: Database,
        configuration: AuditIntegrityConfiguration
    ) async throws {
        try await append(
            kind: .retention,
            auditLogID: auditLogID,
            payloadHash: sha256Hex(canonical([
                "swift-vapor/audit-retention/v1",
                auditLogID.uuidString.lowercased(),
            ])),
            on: database,
            configuration: configuration
        )
    }

    static func verify(
        on database: Database,
        configuration: AuditIntegrityConfiguration
    ) async throws -> AuditIntegrityVerification {
        try await database.transaction { transaction in
            if let sql = transaction as? SQLDatabase,
               sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw("""
                    SELECT id FROM audit_integrity_heads
                    WHERE id = \(bind: AuditIntegrityHead.singletonID)
                    FOR SHARE
                    """).run()
            }
            return try await verifySnapshot(on: transaction, configuration: configuration)
        }
    }

    private static func append(
        kind: AuditIntegrityEventKind,
        auditLogID: UUID,
        payloadHash: String,
        on database: Database,
        configuration: AuditIntegrityConfiguration
    ) async throws {
        guard isSHA256Hex(payloadHash) else { throw LedgerError.invalidDigest }
        try await lockHead(on: database)
        guard let head = try await AuditIntegrityHead.find(
            AuditIntegrityHead.singletonID,
            on: database
        ) else {
            throw LedgerError.headMissing
        }
        guard head.lastSequence < Int64.max else { throw LedgerError.sequenceExhausted }

        let sequence = head.lastSequence + 1
        let eventID = UUID()
        let recordedAt = normalizedTimestamp(Date())
        let publicKey = configuration.publicKeyBytes.base64EncodedString()
        let digest = eventHash(
            eventID: eventID,
            sequence: sequence,
            kind: kind,
            auditLogID: auditLogID,
            payloadHash: payloadHash,
            previousHash: head.headHash,
            signingKeyID: configuration.keyID,
            publicKey: publicKey,
            recordedAt: recordedAt
        )
        guard let digestBytes = dataFromHex(digest) else { throw LedgerError.invalidDigest }
        let signature = try configuration.sign(digestBytes).base64EncodedString()

        let event = AuditIntegrityEvent(
            id: eventID,
            sequence: sequence,
            kind: kind,
            auditLogID: auditLogID,
            payloadHash: payloadHash,
            previousHash: head.headHash,
            entryHash: digest,
            signature: signature,
            signingKeyID: configuration.keyID,
            publicKey: publicKey,
            recordedAt: recordedAt
        )
        try await event.create(on: database)
        head.lastSequence = sequence
        head.headHash = digest
        head.updatedAt = recordedAt
        try await head.update(on: database)
    }

    private static func verifySnapshot(
        on database: Database,
        configuration: AuditIntegrityConfiguration
    ) async throws -> AuditIntegrityVerification {
        let checkedAt = Date()
        guard let head = try await AuditIntegrityHead.find(
            AuditIntegrityHead.singletonID,
            on: database
        ) else {
            throw LedgerError.headMissing
        }
        do {
            let eventCount = try await AuditIntegrityEvent.query(on: database).count()
            guard eventCount <= maximumVerificationEvents else {
                throw VerificationIssue(
                    code: "verification_limit_exceeded", verifiedEvents: 0, legacyLogs: 0
                )
            }
            let events = try await AuditIntegrityEvent.query(on: database)
                .sort(\.$sequence, .ascending)
                .all()
            let chain = try verifyEventChain(events, head: head, configuration: configuration)
            let legacy = try await verifyDisplayLogs(
                on: database,
                chain: chain,
                ledgerStartedAt: head.startedAt,
                configuration: configuration
            )
            return AuditIntegrityVerification(
                status: "valid",
                failureCode: nil,
                verifiedEvents: chain.verifiedEvents,
                legacyUntrackedLogs: legacy,
                lastSequence: head.lastSequence,
                headHash: head.headHash,
                activeSigningKeyID: configuration.keyID,
                checkedAt: checkedAt
            )
        } catch let issue as VerificationIssue {
            return failure(
                issue.code,
                verified: issue.verifiedEvents,
                legacy: issue.legacyLogs,
                head: head,
                configuration: configuration,
                checkedAt: checkedAt
            )
        }
    }

    private static func verifyEventChain(
        _ events: [AuditIntegrityEvent],
        head: AuditIntegrityHead,
        configuration: AuditIntegrityConfiguration
    ) throws -> ChainVerification {
        var expectedSequence: Int64 = 1
        var previousHash = genesisHash
        var verified = 0
        var latestState: [UUID: AuditState] = [:]

        for event in events {
            guard event.sequence == expectedSequence else {
                throw issue("sequence_gap", verified: verified)
            }
            guard event.previousHash == previousHash else {
                throw issue("previous_hash_mismatch", verified: verified)
            }
            guard let eventID = event.id,
                  let kind = event.kind,
                  isSHA256Hex(event.payloadHash),
                  isSHA256Hex(event.previousHash),
                  isSHA256Hex(event.entryHash) else {
                throw issue("event_format_invalid", verified: verified)
            }
            let expectedHash = eventHash(
                eventID: eventID,
                sequence: event.sequence,
                kind: kind,
                auditLogID: event.auditLogID,
                payloadHash: event.payloadHash,
                previousHash: event.previousHash,
                signingKeyID: event.signingKeyID,
                publicKey: event.publicKey,
                recordedAt: event.recordedAt
            )
            guard expectedHash == event.entryHash else {
                throw issue("event_hash_mismatch", verified: verified)
            }
            guard let digest = dataFromHex(event.entryHash),
                  let signature = Data(base64Encoded: event.signature),
                  let publicKeyData = Data(base64Encoded: event.publicKey),
                  let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
            else {
                throw issue("signature_format_invalid", verified: verified)
            }
            guard publicKey.isValidSignature(signature, for: digest) else {
                throw issue("signature_invalid", verified: verified)
            }
            switch (latestState[event.auditLogID]?.kind, kind) {
            case (nil, .entry), (nil, .retention), (.entry?, .redaction),
                 (.redaction?, .redaction), (.entry?, .retention), (.redaction?, .retention):
                break
            default:
                throw issue("event_transition_invalid", verified: verified)
            }
            latestState[event.auditLogID] = AuditState(kind: kind, payloadHash: event.payloadHash)
            previousHash = event.entryHash
            expectedSequence += 1
            verified += 1
        }

        guard head.lastSequence == Int64(events.count), head.headHash == previousHash else {
            throw issue("head_mismatch", verified: verified)
        }
        if let tail = events.last,
           tail.signingKeyID != configuration.keyID
            || Data(base64Encoded: tail.publicKey) != configuration.publicKeyBytes {
            throw issue("active_key_not_anchored", verified: verified)
        }
        return ChainVerification(verifiedEvents: verified, latestState: latestState)
    }

    private static func verifyDisplayLogs(
        on database: Database,
        chain: ChainVerification,
        ledgerStartedAt: Date,
        configuration: AuditIntegrityConfiguration
    ) async throws -> Int {
        let logCount = try await AuditLog.query(on: database).count()
        guard logCount <= maximumVerificationEvents else {
            throw issue("verification_limit_exceeded", verified: chain.verifiedEvents)
        }
        let logs = try await AuditLog.query(on: database).all()
        var logsByID: [UUID: AuditLog] = [:]
        for log in logs {
            guard let id = log.id else {
                throw issue("audit_log_format_invalid", verified: chain.verifiedEvents)
            }
            logsByID[id] = log
        }

        for (logID, state) in chain.latestState {
            if state.kind == .retention {
                guard logsByID[logID] == nil else {
                    throw issue("retained_log_after_tombstone", verified: chain.verifiedEvents)
                }
                continue
            }
            guard let log = logsByID[logID], let timestamp = log.createdAt else {
                throw issue("audit_log_missing", verified: chain.verifiedEvents)
            }
            let currentHash: String
            do {
                currentHash = payloadHash(
                    auditLogID: logID,
                    userID: log.userID,
                    action: log.action,
                    target: try log.target,
                    ip: try log.ip,
                    recordedAt: timestamp,
                    configuration: configuration
                )
            } catch {
                throw issue("audit_log_decryption_failed", verified: chain.verifiedEvents)
            }
            guard currentHash == state.payloadHash else {
                throw issue("audit_log_payload_mismatch", verified: chain.verifiedEvents)
            }
        }

        var legacy = 0
        for log in logs {
            guard let logID = log.id else {
                throw issue("audit_log_format_invalid", verified: chain.verifiedEvents)
            }
            guard chain.latestState[logID] == nil else { continue }
            guard let timestamp = log.createdAt, timestamp <= ledgerStartedAt else {
                throw issue("audit_log_untracked", verified: chain.verifiedEvents, legacy: legacy)
            }
            legacy += 1
        }
        return legacy
    }

    private static func issue(
        _ code: String,
        verified: Int,
        legacy: Int = 0
    ) -> VerificationIssue {
        VerificationIssue(code: code, verifiedEvents: verified, legacyLogs: legacy)
    }

    private static func lockHead(on database: Database) async throws {
        if let sql = database as? SQLDatabase,
           sql.dialect.name.lowercased().contains("postgres") {
            try await sql.raw("""
                SELECT id FROM audit_integrity_heads
                WHERE id = \(bind: AuditIntegrityHead.singletonID)
                FOR UPDATE
                """).run()
        }
    }

    private static func failure(
        _ code: String,
        verified: Int,
        legacy: Int,
        head: AuditIntegrityHead,
        configuration: AuditIntegrityConfiguration,
        checkedAt: Date
    ) -> AuditIntegrityVerification {
        AuditIntegrityVerification(
            status: "invalid",
            failureCode: code,
            verifiedEvents: verified,
            legacyUntrackedLogs: legacy,
            lastSequence: head.lastSequence,
            headHash: head.headHash,
            activeSigningKeyID: configuration.keyID,
            checkedAt: checkedAt
        )
    }

    private static func payloadHash(
        auditLogID: UUID,
        userID: UUID?,
        action: String,
        target: String,
        ip: String,
        recordedAt: Date,
        configuration: AuditIntegrityConfiguration
    ) -> String {
        configuration.commit(canonical([
            "swift-vapor/audit-payload/v1",
            auditLogID.uuidString.lowercased(),
            userID?.uuidString.lowercased() ?? "",
            action,
            target,
            ip,
            String(timestampMilliseconds(recordedAt)),
        ]))
    }

    private static func eventHash(
        eventID: UUID,
        sequence: Int64,
        kind: AuditIntegrityEventKind,
        auditLogID: UUID,
        payloadHash: String,
        previousHash: String,
        signingKeyID: String,
        publicKey: String,
        recordedAt: Date
    ) -> String {
        sha256Hex(canonical([
            "swift-vapor/audit-chain/v1",
            eventID.uuidString.lowercased(),
            String(sequence),
            kind.rawValue,
            auditLogID.uuidString.lowercased(),
            payloadHash,
            previousHash,
            signingKeyID,
            publicKey,
            String(timestampMilliseconds(recordedAt)),
        ]))
    }

    private static func canonical(_ fields: [String]) -> Data {
        var output = Data()
        for field in fields {
            let bytes = Data(field.utf8)
            var length = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { output.append(contentsOf: $0) }
            output.append(bytes)
        }
        return output
    }

    private static func normalizedTimestamp(_ date: Date) -> Date {
        Date(timeIntervalSince1970: Double(timestampMilliseconds(date)) / 1_000)
    }

    private static func timestampMilliseconds(_ date: Date) -> Int64 {
        // Date is backed by a binary floating-point value. Rounding to the
        // nearest millisecond is stable across database encode/decode; truncating
        // can turn an exact logical millisecond into N-1 after a tiny FP drift.
        Int64((date.timeIntervalSince1970 * 1_000).rounded())
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isSHA256Hex(_ value: String) -> Bool {
        value.count == 64
            && value.unicodeScalars.allSatisfy {
                (48...57).contains($0.value) || (97...102).contains($0.value)
            }
    }

    private static func dataFromHex(_ value: String) -> Data? {
        guard isSHA256Hex(value) else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }
}
