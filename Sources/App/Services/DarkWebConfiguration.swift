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
        let secret = try sharedSecret()
        guard let secret else {
            throw Abort(.internalServerError,
                        reason: "A valid dark-web worker shared secret is required when dark-web jobs are enabled.")
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

    private static func sharedSecret() throws -> String? {
        let inline = Environment.get("DARK_WEB_SHARED_SECRET")?.trimmingCharacters(in: .newlines)
        let file = Environment.get("DARK_WEB_SHARED_SECRET_FILE")?
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard inline?.isEmpty != false || file?.isEmpty != false else {
            throw Abort(.internalServerError,
                        reason: "Configure only one dark-web shared-secret source.")
        }

        let secret: String?
        if let file, !file.isEmpty {
            guard file.hasPrefix("/"), file != "/" else {
                throw Abort(.internalServerError,
                            reason: "DARK_WEB_SHARED_SECRET_FILE must be a specific absolute path.")
            }
            let data: Data
            do {
                let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: file))
                defer { try? handle.close() }
                data = try handle.read(upToCount: 513) ?? Data()
            } catch {
                throw Abort(.internalServerError,
                            reason: "The dark-web shared-secret credential cannot be read.")
            }
            guard data.count <= 512, let value = String(data: data, encoding: .utf8) else {
                throw Abort(.internalServerError,
                            reason: "The dark-web shared-secret credential is invalid.")
            }
            secret = value.trimmingCharacters(in: .newlines)
        } else {
            secret = inline
        }

        guard let secret, (32...512).contains(secret.utf8.count),
              secret.unicodeScalars.allSatisfy({ (33...126).contains($0.value) }) else {
            return nil
        }
        return secret
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
