import Foundation

/// Process-lifetime counters surfaced by `/metrics` in Prometheus text format.
///
/// Counters live in an `actor` so increments from any concurrent task are
/// race-free without a lock. Reads happen at scrape time only (≤ 1/min in
/// practice), so the actor's serialisation has zero observable cost.
///
/// Persistence: deliberately none. Process restart resets the counters to 0,
/// which is the standard Prometheus contract for `_total` counters — scrapers
/// detect the reset via the timestamp + value drop and start a new series.
actor MetricsRegistry {
    static let shared = MetricsRegistry()

    private(set) var pluginCacheHits:   UInt64 = 0
    private(set) var pluginCacheMisses: UInt64 = 0

    /// Per-channel notification attempt counts. Channel labels:
    /// "webhook", "discord", "telegram", "slack", "email".
    private(set) var notificationsSent: [String: UInt64] = [:]

    func incPluginCacheHit()   { pluginCacheHits   &+= 1 }
    func incPluginCacheMiss()  { pluginCacheMisses &+= 1 }
    func incNotificationSent(channel: String) {
        notificationsSent[channel, default: 0] &+= 1
    }

    /// Immutable snapshot consumed by the Prometheus formatter. Returned via
    /// the actor barrier so the formatter sees a self-consistent state.
    struct Snapshot: Sendable {
        let pluginCacheHits:   UInt64
        let pluginCacheMisses: UInt64
        let notificationsSent: [String: UInt64]
    }

    func snapshot() -> Snapshot {
        Snapshot(
            pluginCacheHits:   pluginCacheHits,
            pluginCacheMisses: pluginCacheMisses,
            notificationsSent: notificationsSent
        )
    }
}
