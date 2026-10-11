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
        pollSeconds: 30,
        leaseSeconds: 60,
        retentionDays: 30
    )

    static func fromEnvironment() throws -> Self {
        NotificationDeliveryConfiguration(
            enabled: try EnvironmentSetting.boolean("NOTIFICATION_WORKER_ENABLED", fallback: true),
            maxAttempts: try EnvironmentSetting.integer("NOTIFICATION_MAX_ATTEMPTS", fallback: 5, range: 1...10),
            pollSeconds: try EnvironmentSetting.integer("NOTIFICATION_POLL_SECONDS", fallback: 30, range: 1...60),
            leaseSeconds: try EnvironmentSetting.integer("NOTIFICATION_LEASE_SECONDS", fallback: 60, range: 30...300),
            retentionDays: try EnvironmentSetting.integer("NOTIFICATION_RETENTION_DAYS", fallback: 30, range: 1...365)
        )
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
