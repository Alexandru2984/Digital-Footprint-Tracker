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

    /// Bounded channel/outcome labels. A non-skipped delivery increments both
    /// `attempted` and its terminal `succeeded`/`failed` outcome.
    private(set) var notificationDeliveries: [NotificationChannel: [String: UInt64]] = [:]
    private(set) var darkWebJobs: [String: UInt64] = [:]
    private(set) var sensitiveFieldFailures: [FieldCrypto.StoredField: [FieldCrypto.DecryptionReason: UInt64]] = [:]

    func incPluginCacheHit()   { pluginCacheHits   &+= 1 }
    func incPluginCacheMiss()  { pluginCacheMisses &+= 1 }
    func recordNotificationDelivery(
        channel: NotificationChannel, outcome: NotificationDeliveryOutcome
    ) {
        if outcome != .skipped {
            notificationDeliveries[channel, default: [:]]["attempted", default: 0] &+= 1
        }
        notificationDeliveries[channel, default: [:]][outcome.rawValue, default: 0] &+= 1
    }
    func incDarkWebJob(status: String) {
        darkWebJobs[status, default: 0] &+= 1
    }
    func recordSensitiveFieldFailure(
        field: FieldCrypto.StoredField,
        reason: FieldCrypto.DecryptionReason
    ) {
        sensitiveFieldFailures[field, default: [:]][reason, default: 0] &+= 1
    }

    /// Immutable snapshot consumed by the Prometheus formatter. Returned via
    /// the actor barrier so the formatter sees a self-consistent state.
    struct Snapshot: Sendable {
        let pluginCacheHits:   UInt64
        let pluginCacheMisses: UInt64
        let notificationDeliveries: [NotificationChannel: [String: UInt64]]
        let darkWebJobs: [String: UInt64]
        let sensitiveFieldFailures: [FieldCrypto.StoredField: [FieldCrypto.DecryptionReason: UInt64]]
    }

    func snapshot() -> Snapshot {
        Snapshot(
            pluginCacheHits:   pluginCacheHits,
            pluginCacheMisses: pluginCacheMisses,
            notificationDeliveries: notificationDeliveries,
            darkWebJobs: darkWebJobs,
            sensitiveFieldFailures: sensitiveFieldFailures
        )
    }
}
