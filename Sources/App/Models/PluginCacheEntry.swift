import Fluent
import Vapor

/// Encrypted cached plugin output keyed by (plugin name, HMAC-SHA256(normalized input)).
///
/// One row per (plugin, target) pair. The unique constraint on those two
/// columns lets us upsert via delete-then-insert without a transaction race
/// (the worst case is two concurrent scans both writing the same payload —
/// the row content is identical, so the loser of the unique-conflict just
/// retries inside the catch branch).
final class PluginCacheEntry: Model {
    static let schema = "plugin_cache"

    @ID(key: .id)                              var id: UUID?
    @Field(key: "plugin_name")                 var pluginName: String
    @Field(key: "target_hash")                 var targetHash: String
    @Field(key: "payload")                     var payload: String
    @Field(key: "expires_at")                  var expiresAt: Date
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(id: UUID? = nil, pluginName: String, targetHash: String, plaintext: String, expiresAt: Date) {
        let recordID = id ?? UUID()
        self.id = recordID
        self.pluginName = pluginName
        self.targetHash = targetHash
        self.payload = FieldCrypto.encrypt(
            plaintext,
            field: .pluginCachePayload,
            recordID: recordID
        )
        self.expiresAt  = expiresAt
    }
}
