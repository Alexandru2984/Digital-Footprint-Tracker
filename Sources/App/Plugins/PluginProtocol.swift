import Vapor
import Foundation

protocol FootprintPlugin: Sendable {
    var name: String { get }

    /// Human-readable, honest one-liner shown in the plugin picker. Defaults to
    /// a generic label; every shipping plugin overrides it (enforced by a test).
    var description: String { get }

    /// How long this plugin's output stays fresh in `PluginCacheStore`. Declared
    /// per-plugin so the TTL can never drift from the plugin's `name` (the old
    /// central string→TTL map silently fell back to the default whenever a key
    /// failed to match a renamed plugin).
    var cacheTTL: TimeInterval { get }

    /// Expensive plugins (many outbound requests per run) set this true so the
    /// candidate fan-out runs them on at most one derived candidate instead of
    /// every speculative variant — see `TargetDeriver.Origin.heavyEligible`.
    var heavy: Bool { get }

    /// The input shapes this plugin can act on. `ScanPluginRunner` skips a
    /// (plugin, candidate) pair outright when the candidate's shape isn't in
    /// here — no cache lookup, no `scan` call, no empty cache row written back.
    ///
    /// Declare the shapes the plugin *might* handle, not the exact ones: this
    /// is a coarse pre-filter and the plugin's own guard stays the authority.
    /// The default admits everything, which is exactly the behaviour before this
    /// existed; a test asserts every shipping plugin narrows it.
    var accepts: Set<TargetShape> { get }

    /// The runtime secret this plugin cannot work without, or nil. A plugin
    /// whose secret is not configured is never run: it could only answer
    /// "nothing found", which reads as a clean result (no breaches, no open
    /// ports) when nothing was checked at all.
    var requiredSecret: String? { get }

    /// Bumped whenever the shape or meaning of this plugin's results changes.
    /// It is part of the cache key, so results cached by an older release are
    /// not served after a deploy (otherwise a fix to, say, how a clean verdict
    /// is typed shows up only once the old entries expire, up to a day later).
    var cacheVersion: Int { get }

    // Using Application instead of Request allows safe background execution
    func scan(input: String, on app: Application) async throws -> [PluginResult]
}

extension FootprintPlugin {
    var description: String { "OSINT plugin" }
    var cacheTTL: TimeInterval { 3600 } // 1 hour
    var heavy: Bool { false }
    var accepts: Set<TargetShape> { TargetShape.all }
    var requiredSecret: String? { nil }
    var cacheVersion: Int { 1 }

    /// The plugin cache key: the name, plus the version once it has moved.
    var cacheKey: String { cacheVersion == 1 ? name : "\(name)#v\(cacheVersion)" }

    /// False when `requiredSecret` is set and not configured (or configured
    /// wrongly: an unreadable secret is not a usable one).
    var isConfigured: Bool {
        guard let secret = requiredSecret else { return true }
        guard let value = try? RuntimeSecret.value(secret) else { return false }
        return !value.isEmpty
    }
}

struct PluginResult: Sendable, Codable {
    let source: String
    let type: String
    let confidenceScore: Double
    let rawData: String
    /// Optional structured entities for correlation / machine-readable export
    /// (e.g. ["platform": "github", "username": "alice", "location": "NYC"]).
    /// Optional so cached JSON written before this field existed still decodes.
    let metadata: [String: String]?

    init(source: String, type: String, confidenceScore: Double, rawData: String, metadata: [String: String]? = nil) {
        self.source = source
        self.type = type
        self.confidenceScore = confidenceScore
        self.rawData = rawData
        self.metadata = metadata
    }
}
