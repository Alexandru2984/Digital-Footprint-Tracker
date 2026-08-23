import Fluent
import Vapor

/// A saved graph-based investigation ("board"): a persisted, growing relationship
/// graph the user builds by expanding entities in the graph UI (FlowSint-style).
///
/// The board's `data` is the serialised graph (`{"nodes":[…],"edges":[…]}`) and is
/// encrypted at rest via `FieldCrypto` — it names WHO/WHAT is under investigation
/// (emails, usernames, domains), the most sensitive metadata in the app. Owner-only:
/// there are no anonymous boards.
final class Investigation: Model {
    static let schema = "investigations"

    @ID(key: .id)
    var id: UUID?

    @Parent(key: "user_id")
    var user: User

    @Field(key: "name")
    var nameCipher: String
    var name: String {
        get throws {
            try FieldCrypto.decryptStored(nameCipher, field: .investigationName, recordID: id)
        }
    }
    func setName(_ newValue: String) {
        nameCipher = FieldCrypto.encrypt(newValue, field: .investigationName, recordID: encryptionID)
    }

    /// Ciphertext at rest — the graph JSON. Read/written via the `data` accessor.
    @Field(key: "data")
    var dataCipher: String

    /// Plaintext view of the graph JSON (decrypts on read, encrypts on write).
    var data: String {
        get throws {
            try FieldCrypto.decryptStored(dataCipher, field: .investigationData, recordID: id)
        }
    }
    func setData(_ newValue: String) {
        dataCipher = FieldCrypto.encrypt(newValue, field: .investigationData, recordID: encryptionID)
    }

    // ── Live monitoring ("watched" board) ─────────────────────────────────
    /// When true, a background runner periodically re-scans the board's active
    /// entities and merges any net-new nodes/edges (flagged `new` in the graph).
    @Field(key: "watched")
    var watched: Bool

    /// "daily" | "weekly" — how often a watched board is re-checked.
    @OptionalField(key: "watch_interval")
    var watchInterval: String?

    @OptionalField(key: "next_check_at")
    var nextCheckAt: Date?

    @OptionalField(key: "last_checked_at")
    var lastCheckedAt: Date?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() { }

    init(id: UUID? = nil, userID: UUID, name: String, data: String) {
        let recordID = id ?? UUID()
        self.id = recordID
        self.$user.id = userID
        self.nameCipher = FieldCrypto.encrypt(name, field: .investigationName, recordID: recordID)
        self.dataCipher = FieldCrypto.encrypt(data, field: .investigationData, recordID: recordID)
        self.watched = false
    }

    private var encryptionID: UUID {
        guard let id else { preconditionFailure("Investigation must have an ID before encryption") }
        return id
    }
}
