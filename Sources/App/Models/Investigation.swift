import Fluent
import Vapor

/// A saved graph-based investigation ("board"): a persisted, growing relationship
/// graph the user builds by expanding entities in the graph UI (FlowSint-style).
///
/// The board's `data` is the serialised graph (`{"nodes":[…],"edges":[…]}`) and is
/// encrypted at rest via `FieldCrypto` — it names WHO/WHAT is under investigation
/// (emails, usernames, domains), the most sensitive metadata in the app. Owner-only:
/// there are no anonymous boards.
final class Investigation: Model, Content {
    static let schema = "investigations"

    @ID(key: .id)
    var id: UUID?

    @Parent(key: "user_id")
    var user: User

    @Field(key: "name")
    var name: String

    /// Ciphertext at rest — the graph JSON. Read/written via the `data` accessor.
    @Field(key: "data")
    var dataCipher: String

    /// Plaintext view of the graph JSON (decrypts on read, encrypts on write).
    var data: String {
        get { FieldCrypto.decrypt(dataCipher) ?? dataCipher }
        set { dataCipher = FieldCrypto.encrypt(newValue) }
    }

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() { }

    init(id: UUID? = nil, userID: UUID, name: String, data: String) {
        self.id = id
        self.$user.id = userID
        self.name = name
        self.data = data   // computed setter encrypts
    }
}
