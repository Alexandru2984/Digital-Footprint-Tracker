import Fluent
import Vapor

enum ScanStatus: String, Codable {
    case pending
    case completed
    case failed
}

final class Scan: Model, Content {
    static let schema = "scans"

    @ID(key: .id)
    var id: UUID?

    /// Ciphertext at rest — the target identifier (email / username / domain /
    /// phone) is the most sensitive metadata a scan carries: it names WHO is being
    /// investigated. Read/written only through the computed `input` accessor.
    @Field(key: "input")
    var inputCipher: String

    /// Blind index (HMAC of the normalized plaintext) so dedup / reuse / diff can
    /// still look a scan up by input without the column being queryable in the
    /// clear. Nil on rows created before encryption was introduced (those keep a
    /// plaintext `input` and are matched by the legacy equality branch instead).
    @OptionalField(key: "input_hash")
    var inputHash: String?

    /// Plaintext view of the target. Decrypts on read (legacy plaintext rows fall
    /// through unchanged). Mutations go through `setInput`, which encrypts and
    /// refreshes the blind index.
    var input: String {
        get throws {
            try FieldCrypto.decryptStored(inputCipher, field: .scanInput, recordID: id)
        }
    }

    func setInput(_ newValue: String) {
        inputCipher = FieldCrypto.encrypt(newValue, field: .scanInput, recordID: encryptionID)
        inputHash = FieldCrypto.blindIndex(newValue)
    }

    @Field(key: "status")
    var statusRaw: String

    var status: ScanStatus {
        get { ScanStatus(rawValue: statusRaw) ?? .pending }
        set { statusRaw = newValue.rawValue }
    }

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @OptionalField(key: "completed_at")
    var completedAt: Date?

    @Children(for: \.$scan)
    var results: [Result]

    @OptionalParent(key: "user_id")
    var user: User?

    @Siblings(through: ScanTag.self, from: \.$scan, to: \.$tag)
    var tags: [Tag]

    init() { }

    init(id: UUID? = nil, input: String, status: ScanStatus = .pending, userID: UUID? = nil) {
        let recordID = id ?? UUID()
        self.id = recordID
        self.inputCipher = FieldCrypto.encrypt(input, field: .scanInput, recordID: recordID)
        self.inputHash = FieldCrypto.blindIndex(input)
        self.statusRaw = status.rawValue
        self.$user.id = userID
    }

    private var encryptionID: UUID {
        guard let id else { preconditionFailure("Scan must have an ID before encryption") }
        return id
    }
}

extension QueryBuilder where Model == Scan {
    /// Match a scan by its target input, transparently covering both encrypted
    /// rows (looked up by blind index) and legacy plaintext rows (looked up by the
    /// raw column). Use this instead of `filter(\.$input == …)`, which no longer
    /// exists now that the column holds ciphertext.
    func filterInput(_ plaintext: String) -> Self {
        let hashes = FieldCrypto.blindIndexCandidates(plaintext)
        return self.group(.or) { or in
            or.filter(\.$inputHash ~~ hashes)
            or.filter(\.$inputCipher == plaintext)
        }
    }
}
