import Fluent
import Foundation

enum AuditIntegrityEventKind: String, Codable, CaseIterable, Sendable {
    case entry
    case redaction
    case retention
}

/// Privacy-minimal, immutable commitment to one human-readable audit-log state.
///
/// The target and IP never enter this table. `payloadHash` commits to those
/// values, while the signed hash chain makes deletion, insertion and reordering
/// detectable without turning the integrity ledger into another PII store.
final class AuditIntegrityEvent: Model {
    static let schema = "audit_integrity_events"

    @ID(key: .id) var id: UUID?
    @Field(key: "sequence") var sequence: Int64
    @Field(key: "kind") var kindRaw: String
    @Field(key: "audit_log_id") var auditLogID: UUID
    @Field(key: "payload_hash") var payloadHash: String
    @Field(key: "previous_hash") var previousHash: String
    @Field(key: "entry_hash") var entryHash: String
    @Field(key: "signature") var signature: String
    @Field(key: "signing_key_id") var signingKeyID: String
    @Field(key: "public_key") var publicKey: String
    @Field(key: "recorded_at") var recordedAt: Date

    var kind: AuditIntegrityEventKind? {
        AuditIntegrityEventKind(rawValue: kindRaw)
    }

    init() {}

    init(
        id: UUID = UUID(),
        sequence: Int64,
        kind: AuditIntegrityEventKind,
        auditLogID: UUID,
        payloadHash: String,
        previousHash: String,
        entryHash: String,
        signature: String,
        signingKeyID: String,
        publicKey: String,
        recordedAt: Date
    ) {
        self.id = id
        self.sequence = sequence
        self.kindRaw = kind.rawValue
        self.auditLogID = auditLogID
        self.payloadHash = payloadHash
        self.previousHash = previousHash
        self.entryHash = entryHash
        self.signature = signature
        self.signingKeyID = signingKeyID
        self.publicKey = publicKey
        self.recordedAt = recordedAt
    }
}

/// The single mutable cursor used only to serialize writers and anchor the
/// expected tail. The immutable event table remains the source of truth.
final class AuditIntegrityHead: Model {
    static let schema = "audit_integrity_heads"
    static let singletonID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!

    @ID(key: .id) var id: UUID?
    @Field(key: "last_sequence") var lastSequence: Int64
    @Field(key: "head_hash") var headHash: String
    @Field(key: "started_at") var startedAt: Date
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    init(startedAt: Date) {
        self.id = Self.singletonID
        self.lastSequence = 0
        self.headHash = AuditIntegrityLedger.genesisHash
        self.startedAt = startedAt
        self.updatedAt = startedAt
    }
}
