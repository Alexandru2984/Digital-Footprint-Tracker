import Vapor
import XCTest
@testable import App

final class MigrationPolicyTests: XCTestCase {
    func testNonProductionAlwaysMigrates() throws {
        XCTAssertTrue(try MigrationPolicy.shouldAutoMigrate(
            environment: .testing,
            productionSetting: nil
        ))
        XCTAssertTrue(try MigrationPolicy.shouldAutoMigrate(
            environment: .development,
            productionSetting: "false"
        ))
    }

    func testProductionRequiresExplicitOptIn() throws {
        XCTAssertFalse(try MigrationPolicy.shouldAutoMigrate(
            environment: .production,
            productionSetting: nil
        ))
        XCTAssertFalse(try MigrationPolicy.shouldAutoMigrate(
            environment: .production,
            productionSetting: "false"
        ))
        XCTAssertTrue(try MigrationPolicy.shouldAutoMigrate(
            environment: .production,
            productionSetting: "true"
        ))
    }

    func testProductionRejectsAmbiguousValue() {
        XCTAssertThrowsError(try MigrationPolicy.shouldAutoMigrate(
            environment: .production,
            productionSetting: "sometimes"
        ))
    }
}
