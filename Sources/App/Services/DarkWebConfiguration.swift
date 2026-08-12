import Foundation
import Vapor

struct DarkWebConfiguration: Sendable {
    static let defaultRetentionHours = 72
    static let maximumRetentionHours = 168

    let enabled: Bool
    let workerURL: URL?
    let sharedSecret: String?
    let retentionHours: Int
    let maxOutstandingJobs: Int
    let maxJobsPerUserPerDay: Int
    let jobTimeoutSeconds: Int

    static let disabled = DarkWebConfiguration(
        enabled: false,
        workerURL: nil,
        sharedSecret: nil,
        retentionHours: defaultRetentionHours,
        maxOutstandingJobs: 5,
        maxJobsPerUserPerDay: 3,
        jobTimeoutSeconds: 600
    )

    static func fromEnvironment() throws -> Self {
        let enabled = parseBool(Environment.get("DARK_WEB_ENABLED")) ?? false
        let retention = boundedInt(
            Environment.get("DARK_WEB_RETENTION_HOURS"),
            fallback: defaultRetentionHours,
            range: 1...maximumRetentionHours
        )
        let maxOutstanding = boundedInt(
            Environment.get("DARK_WEB_MAX_OUTSTANDING"), fallback: 5, range: 1...10
        )
        let maxDaily = boundedInt(
            Environment.get("DARK_WEB_MAX_JOBS_PER_USER_DAY"), fallback: 3, range: 1...10
        )
        let timeout = boundedInt(
            Environment.get("DARK_WEB_JOB_TIMEOUT_SECONDS"), fallback: 600, range: 60...900
        )

        guard enabled else {
            return DarkWebConfiguration(
                enabled: false,
                workerURL: nil,
                sharedSecret: nil,
                retentionHours: retention,
                maxOutstandingJobs: maxOutstanding,
                maxJobsPerUserPerDay: maxDaily,
                jobTimeoutSeconds: timeout
            )
        }

        guard let rawURL = Environment.get("DARK_WEB_WORKER_URL"),
              let workerURL = URL(string: rawURL),
              workerURL.scheme?.lowercased() == "http",
              let host = workerURL.host?.lowercased(),
              host == "127.0.0.1" || host == "::1" || host == "localhost",
              workerURL.user == nil, workerURL.password == nil,
              (workerURL.path.isEmpty || workerURL.path == "/"),
              workerURL.query == nil, workerURL.fragment == nil else {
            throw Abort(.internalServerError,
                        reason: "DARK_WEB_WORKER_URL must be an HTTP loopback origin without credentials or a path.")
        }
        guard let secret = Environment.get("DARK_WEB_SHARED_SECRET"), secret.utf8.count >= 32 else {
            throw Abort(.internalServerError,
                        reason: "DARK_WEB_SHARED_SECRET must contain at least 32 bytes when dark-web jobs are enabled.")
        }

        return DarkWebConfiguration(
            enabled: true,
            workerURL: workerURL,
            sharedSecret: secret,
            retentionHours: retention,
            maxOutstandingJobs: maxOutstanding,
            maxJobsPerUserPerDay: maxDaily,
            jobTimeoutSeconds: timeout
        )
    }

    private static func parseBool(_ raw: String?) -> Bool? {
        switch raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "1", "true", "yes": return true
        case "0", "false", "no": return false
        default: return nil
        }
    }

    private static func boundedInt(_ raw: String?, fallback: Int, range: ClosedRange<Int>) -> Int {
        guard let raw, let value = Int(raw), range.contains(value) else { return fallback }
        return value
    }
}

private struct DarkWebConfigurationKey: StorageKey {
    typealias Value = DarkWebConfiguration
}

extension Application {
    var darkWebConfiguration: DarkWebConfiguration {
        get { storage[DarkWebConfigurationKey.self] ?? .disabled }
        set { storage[DarkWebConfigurationKey.self] = newValue }
    }
}
