import Fluent
import Vapor

/// A single OSINT finding.
///
/// Privacy-first storage: the two fields that actually carry harvested PII —
/// `rawData` (the human-readable finding: breach records, exposed emails/phones,
/// leaked content) and `metadata` (structured entities) — are encrypted at rest
/// with AES-256-GCM (see `TokenEncryption`). The database column holds ciphertext;
/// the app only ever sees plaintext through the computed `rawData` / `metadata`
/// accessors. A stolen DB dump or backup is inert without `ENCRYPTION_KEY`.
///
/// Encryption lives behind throwing read accessors, explicit mutation methods,
/// and custom Codable. Fluent's row I/O uses the `@Field` wrappers below
/// (ciphertext); JSON uses the custom `encode(to:)` (plaintext). A damaged tagged
/// value therefore propagates a typed failure instead of terminating the process.
///
/// Backward compatible: rows written before encryption was introduced hold
/// plaintext. `TokenEncryption.decrypt` returns nil for a non-ciphertext value,
/// so the getter falls back to the raw stored string — no data migration needed.
final class Result: Model, Content {
    static let schema = "results"

    @ID(key: .id)
    var id: UUID?

    @Parent(key: "scan_id")
    var scan: Scan

    @Field(key: "source")
    var source: String

    @Field(key: "type")
    var type: String

    @Field(key: "confidence_score")
    var confidenceScore: Double

    /// Ciphertext at rest — read/written only through `rawData`.
    @Field(key: "raw_data")
    var rawDataCipher: String

    /// Ciphertext at rest — read/written only through `metadata`.
    @OptionalField(key: "metadata")
    var metadataCipher: String?

    /// Plaintext view of the finding. Decrypts on read (falling back to the raw
    /// value for legacy plaintext rows); mutations go through `setRawData`.
    var rawData: String {
        get throws {
            try FieldCrypto.decryptStored(rawDataCipher, field: .resultRawData, recordID: id)
        }
    }

    /// Plaintext view of the structured metadata JSON string.
    var metadata: String? {
        get throws {
            try metadataCipher.map {
                try FieldCrypto.decryptStored($0, field: .resultMetadata, recordID: id)
            }
        }
    }

    func setRawData(_ newValue: String) { rawDataCipher = Result.encryptField(newValue) }
    func setMetadata(_ newValue: String?) { metadataCipher = newValue.map(Result.encryptField) }

    init() { }

    init(id: UUID? = nil, scanID: UUID, source: String, type: String, confidenceScore: Double, rawData: String, metadata: String? = nil) {
        self.id = id
        self.$scan.id = scanID
        self.source = source
        self.type = type
        self.confidenceScore = confidenceScore
        self.rawDataCipher = Result.encryptField(rawData)
        self.metadataCipher = metadata.map(Result.encryptField)
    }

    /// Decodes the stored `metadata` JSON string into a dictionary for API
    /// responses and exports. Returns nil when absent or unparseable.
    var metadataObject: [String: String]? {
        get throws {
            guard let metadata = try metadata, let data = metadata.data(using: .utf8) else { return nil }
            return try? JSONDecoder().decode([String: String].self, from: data)
        }
    }

    // MARK: - Field encryption helpers

    /// Encrypt when a key is configured. Production requires a valid key at startup;
    /// encryption errors fail closed before a finding can be persisted.
    static func encryptField(_ plaintext: String) -> String { FieldCrypto.encrypt(plaintext) }

    /// Returns plaintext if `stored` is decryptable ciphertext, else nil (caller
    /// falls back to treating it as a legacy plaintext value).
    static func decryptField(_ stored: String) -> String? { FieldCrypto.decrypt(stored) }

    // MARK: - Codable (plaintext JSON, identical shape to the pre-encryption model)

    enum CodingKeys: String, CodingKey {
        case id, scan, source, type, confidenceScore, rawData, metadata
    }
    private struct ScanRef: Codable { let id: UUID? }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(ScanRef(id: $scan.id), forKey: .scan)
        try c.encode(source, forKey: .source)
        try c.encode(type, forKey: .type)
        try c.encode(confidenceScore, forKey: .confidenceScore)
        try c.encode(try rawData, forKey: .rawData)
        if let metadata = try metadata {
            try c.encode(metadata, forKey: .metadata)
        } else {
            try c.encodeNil(forKey: .metadata)
        }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decodeIfPresent(UUID.self, forKey: .id)
        if let ref = try c.decodeIfPresent(ScanRef.self, forKey: .scan), let sid = ref.id {
            self.$scan.id = sid
        }
        self.source = try c.decode(String.self, forKey: .source)
        self.type = try c.decode(String.self, forKey: .type)
        self.confidenceScore = try c.decode(Double.self, forKey: .confidenceScore)
        self.rawDataCipher = Result.encryptField(try c.decode(String.self, forKey: .rawData))
        self.metadataCipher = try c.decodeIfPresent(String.self, forKey: .metadata).map(Result.encryptField)
    }
}
