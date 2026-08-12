import Foundation
import Vapor

enum BackupStatus {
    static let defaultPath = "/var/lib/swift-vapor-backup/last-success"
    static let defaultMaxAgeSeconds = 30 * 60 * 60

    struct Snapshot {
        let lastSuccessUnix: Int
        let ageSeconds: Int
        let isFresh: Bool
    }

    static func current(now: Date = Date()) -> Snapshot? {
        let path = Environment.get("BACKUP_STATUS_FILE") ?? defaultPath
        let configuredAge = Environment.get("BACKUP_MAX_AGE_SECONDS").flatMap(Int.init)
        let maxAge = configuredAge.map { min(max($0, 3_600), 7 * 86_400) }
            ?? defaultMaxAgeSeconds
        return read(path: path, now: now, maxAgeSeconds: maxAge)
    }

    static func read(
        path: String,
        now: Date = Date(),
        maxAgeSeconds: Int = defaultMaxAgeSeconds
    ) -> Snapshot? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let fileType = attributes[.type] as? FileAttributeType,
              fileType == .typeRegular,
              let size = attributes[.size] as? NSNumber,
              size.intValue <= 32,
              let value = try? String(contentsOfFile: path, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines),
              value.count == 10,
              value.allSatisfy(\.isNumber),
              let timestamp = Int(value) else {
            return nil
        }

        let nowUnix = Int(now.timeIntervalSince1970)
        let age = nowUnix - timestamp
        guard timestamp > 0, age >= -300 else { return nil }
        return Snapshot(
            lastSuccessUnix: timestamp,
            ageSeconds: max(0, age),
            isFresh: age <= maxAgeSeconds
        )
    }
}
