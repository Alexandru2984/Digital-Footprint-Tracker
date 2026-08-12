import Fluent
import Foundation

/// Removes the implicit "forever" lifetime from links created before expiring
/// shares became mandatory. Existing links receive a seven-day grace period
/// from the deployment that applies this migration, so owners can replace or
/// revoke them without preserving an unbounded bearer capability.
struct ExpireLegacySharedReports: AsyncMigration {
    func prepare(on database: Database) async throws {
        let graceDeadline = Date().addingTimeInterval(
            TimeInterval(ShareController.defaultExpirySeconds)
        )
        try await SharedReport.query(on: database)
            .filter(\.$expiresAt == nil)
            .set(\.$expiresAt, to: graceDeadline)
            .update()
    }

    func revert(on database: Database) async throws {
        // Expiry provenance is not recoverable. A rollback must not silently
        // recreate permanent bearer links.
    }
}
