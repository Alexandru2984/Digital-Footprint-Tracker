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
/// Transparency: encryption lives entirely behind the computed accessors and a
/// custom Codable, so every existing call site (`result.rawData`, JSON responses,
/// exports) is unchanged. Fluent's row I/O uses the `@Field` wrappers below
/// (ciphertext); JSON uses the custom `encode(to:)` (plaintext).
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
    /// value for legacy plaintext rows), encrypts on write.
    var rawData: String {
        get { Result.decryptField(rawDataCipher) ?? rawDataCipher }
        set { rawDataCipher = Result.encryptField(newValue) }
    }

    /// Plaintext view of the structured metadata JSON string.
    var metadata: String? {
        get { metadataCipher.flatMap { Result.decryptField($0) ?? $0 } }
        set { metadataCipher = newValue.map { Result.encryptField($0) } }
    }

    init() { }

    init(id: UUID? = nil, scanID: UUID, source: String, type: String, confidenceScore: Double, rawData: String, metadata: String? = nil) {
        self.id = id
        self.$scan.id = scanID
        self.source = source
        self.type = type
        self.confidenceScore = confidenceScore
        self.rawData = rawData        // computed setter encrypts
        self.metadata = metadata      // computed setter encrypts
    }

    /// Decodes the stored `metadata` JSON string into a dictionary for API
    /// responses and exports. Returns nil when absent or unparseable.
    var metadataObject: [String: String]? {
        guard let metadata, let data = metadata.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode([String: String].self, from: data)
    }

    // MARK: - Field encryption helpers

    /// Encrypt when a key is configured; otherwise store plaintext. Fail-open to
    /// plaintext on an unexpected encrypt error so a background scan never loses a
    /// finding (with a valid `ENCRYPTION_KEY` this path is unreachable).
    static func encryptField(_ plaintext: String) -> String {
        guard TokenEncryption.isAvailable() else { return plaintext }
        return (try? TokenEncryption.encrypt(plaintext)) ?? plaintext
    }

    /// Returns plaintext if `stored` is decryptable ciphertext, else nil (caller
    /// falls back to treating it as a legacy plaintext value).
    static func decryptField(_ stored: String) -> String? {
        TokenEncryption.decrypt(stored)
    }

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
        try c.encode(rawData, forKey: .rawData)
        if let m = metadata { try c.encode(m, forKey: .metadata) } else { try c.encodeNil(forKey: .metadata) }
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
        self.rawData = try c.decode(String.self, forKey: .rawData)
        self.metadata = try c.decodeIfPresent(String.self, forKey: .metadata)
    }
}
