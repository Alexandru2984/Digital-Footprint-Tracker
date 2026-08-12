import Foundation
import XCTest
@testable import App

final class BackupStatusTests: XCTestCase {
    func testBackupStatusRejectsMissingMalformedAndFutureTimestamps() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("backup-status-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let status = directory.appendingPathComponent("last-success")
        let now = Date(timeIntervalSince1970: 2_000_000_000)

        XCTAssertNil(BackupStatus.read(path: status.path, now: now))
        try Data("not-a-time\n".utf8).write(to: status)
        XCTAssertNil(BackupStatus.read(path: status.path, now: now))
        try Data("2000000600\n".utf8).write(to: status)
        XCTAssertNil(BackupStatus.read(path: status.path, now: now))
    }

    func testBackupStatusReportsAgeAndFreshness() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("backup-status-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let status = directory.appendingPathComponent("last-success")
        try Data("1999996400\n".utf8).write(to: status)

        let snapshot = try XCTUnwrap(BackupStatus.read(
            path: status.path,
            now: Date(timeIntervalSince1970: 2_000_000_000),
            maxAgeSeconds: 7_200
        ))
        XCTAssertEqual(snapshot.lastSuccessUnix, 1_999_996_400)
        XCTAssertEqual(snapshot.ageSeconds, 3_600)
        XCTAssertTrue(snapshot.isFresh)
    }
}
