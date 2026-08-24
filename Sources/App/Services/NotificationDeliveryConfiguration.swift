import Foundation
import Vapor

struct NotificationDeliveryConfiguration: Sendable {
    let enabled: Bool
    let maxAttempts: Int
    let pollSeconds: Int
    let leaseSeconds: Int
    let retentionDays: Int

    static let defaults = NotificationDeliveryConfiguration(
        enabled: true,
        maxAttempts: 5,
        pollSeconds: 2,
        leaseSeconds: 60,
        retentionDays: 30
    )

    static func fromEnvironment() throws -> Self {
        NotificationDeliveryConfiguration(
            enabled: try boolean("NOTIFICATION_WORKER_ENABLED", fallback: true),
            maxAttempts: try integer("NOTIFICATION_MAX_ATTEMPTS", fallback: 5, range: 1...10),
            pollSeconds: try integer("NOTIFICATION_POLL_SECONDS", fallback: 2, range: 1...60),
            leaseSeconds: try integer("NOTIFICATION_LEASE_SECONDS", fallback: 60, range: 30...300),
            retentionDays: try integer("NOTIFICATION_RETENTION_DAYS", fallback: 30, range: 1...365)
        )
    }

    private static func boolean(_ name: String, fallback: Bool) throws -> Bool {
        guard let raw = Environment.get(name)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else { return fallback }
        switch raw.lowercased() {
        case "1", "true", "yes": return true
        case "0", "false", "no": return false
        default:
            throw Abort(.internalServerError, reason: "\(name) must be an explicit boolean.")
        }
    }

    private static func integer(
        _ name: String,
        fallback: Int,
        range: ClosedRange<Int>
    ) throws -> Int {
        guard let raw = Environment.get(name)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else { return fallback }
        guard let value = Int(raw), range.contains(value) else {
            throw Abort(
                .internalServerError,
                reason: "\(name) must be an integer in \(range.lowerBound)...\(range.upperBound)."
            )
        }
        return value
    }
}

private struct NotificationDeliveryConfigurationKey: StorageKey {
    typealias Value = NotificationDeliveryConfiguration
}

extension Application {
    var notificationDeliveryConfiguration: NotificationDeliveryConfiguration {
        get { storage[NotificationDeliveryConfigurationKey.self] ?? .defaults }
        set { storage[NotificationDeliveryConfigurationKey.self] = newValue }
    }
}
