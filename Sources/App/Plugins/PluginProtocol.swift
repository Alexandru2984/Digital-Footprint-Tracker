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

    // Using Application instead of Request allows safe background execution
    func scan(input: String, on app: Application) async throws -> [PluginResult]
}

extension FootprintPlugin {
    var description: String { "OSINT plugin" }
    var cacheTTL: TimeInterval { 3600 } // 1 hour
}

struct PluginResult: Sendable, Codable {
    let source: String
    let type: String
    let confidenceScore: Double
    let rawData: String
}
