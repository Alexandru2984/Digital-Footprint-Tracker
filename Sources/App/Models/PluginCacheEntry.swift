import Fluent
import Vapor

/// Cached plugin output keyed by (plugin name, sha256(normalized input)).
///
/// One row per (plugin, target) pair. The unique constraint on those two
/// columns lets us upsert via delete-then-insert without a transaction race
/// (the worst case is two concurrent scans both writing the same payload —
/// the row content is identical, so the loser of the unique-conflict just
/// retries inside the catch branch).
final class PluginCacheEntry: Model, Content {
    static let schema = "plugin_cache"

    @ID(key: .id)                              var id: UUID?
    @Field(key: "plugin_name")                 var pluginName: String
    @Field(key: "target_hash")                 var targetHash: String
    @Field(key: "payload")                     var payload: String
    @Field(key: "expires_at")                  var expiresAt: Date
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}
    init(pluginName: String, targetHash: String, payload: String, expiresAt: Date) {
        self.pluginName = pluginName
        self.targetHash = targetHash
        self.payload    = payload
        self.expiresAt  = expiresAt
    }
}
