import Foundation
import Vapor

struct ExportJobConfiguration: Sendable {
    let enabled: Bool
    let pollSeconds: Int
    let leaseSeconds: Int
    let retentionHours: Int
    let maxOutstandingPerUser: Int
    let maxJobsPerUserPerDay: Int
    let maxResults: Int
    let batchSize: Int
    let maxSourceBytes: Int
    let maxArtifactBytes: Int
    let maxAttempts: Int

    static let defaults = ExportJobConfiguration(
        enabled: true,
        pollSeconds: 2,
        leaseSeconds: 120,
        retentionHours: 24,
        maxOutstandingPerUser: 3,
        maxJobsPerUserPerDay: 20,
        maxResults: 10_000,
        batchSize: 250,
        maxSourceBytes: 10 * 1_024 * 1_024,
        maxArtifactBytes: 20 * 1_024 * 1_024,
        maxAttempts: 2
    )

    static func fromEnvironment() throws -> Self {
        ExportJobConfiguration(
            enabled: try boolean("EXPORT_WORKER_ENABLED", fallback: true),
            pollSeconds: try integer("EXPORT_POLL_SECONDS", fallback: 2, range: 1...60),
            leaseSeconds: try integer("EXPORT_LEASE_SECONDS", fallback: 120, range: 60...600),
            retentionHours: try integer("EXPORT_RETENTION_HOURS", fallback: 24, range: 1...168),
            maxOutstandingPerUser: try integer("EXPORT_MAX_OUTSTANDING_PER_USER", fallback: 3, range: 1...20),
            maxJobsPerUserPerDay: try integer("EXPORT_MAX_JOBS_PER_USER_PER_DAY", fallback: 20, range: 1...200),
            maxResults: try integer("EXPORT_MAX_RESULTS", fallback: 10_000, range: 1...50_000),
            batchSize: try integer("EXPORT_BATCH_SIZE", fallback: 250, range: 25...1_000),
            maxSourceBytes: try mebibytes("EXPORT_MAX_SOURCE_MIB", fallback: 10, range: 1...16),
            maxArtifactBytes: try mebibytes("EXPORT_MAX_ARTIFACT_MIB", fallback: 20, range: 1...32),
            maxAttempts: try integer("EXPORT_MAX_ATTEMPTS", fallback: 2, range: 1...3)
        )
    }

    private static func boolean(_ name: String, fallback: Bool) throws -> Bool {
        guard let raw = Environment.get(name)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else { return fallback }
        switch raw.lowercased() {
        case "1", "true", "yes": return true
        case "0", "false", "no": return false
        default: throw Abort(.internalServerError, reason: "\(name) must be an explicit boolean.")
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

    private static func mebibytes(
        _ name: String,
        fallback: Int,
        range: ClosedRange<Int>
    ) throws -> Int {
        try integer(name, fallback: fallback, range: range) * 1_024 * 1_024
    }
}

private struct ExportJobConfigurationKey: StorageKey {
    typealias Value = ExportJobConfiguration
}

extension Application {
    var exportJobConfiguration: ExportJobConfiguration {
        get { storage[ExportJobConfigurationKey.self] ?? .defaults }
        set { storage[ExportJobConfigurationKey.self] = newValue }
    }
}
