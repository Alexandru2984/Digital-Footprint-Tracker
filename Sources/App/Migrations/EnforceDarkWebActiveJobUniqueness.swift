import Fluent
import SQLKit

/// Closes the check-then-insert race in the dark-web queue for both fresh and
/// already-migrated databases. This must remain a separate migration: changing
/// `CreateDarkWebInvestigations` would not update deployments that already ran
/// that migration.
struct EnforceDarkWebActiveJobUniqueness: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }
        try await sql.raw(
            "CREATE UNIQUE INDEX IF NOT EXISTS dark_web_investigations_one_active_user_idx " +
            "ON dark_web_investigations (user_id) " +
            "WHERE status IN ('pending', 'running')"
        ).run()
    }

    func revert(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }
        try await sql.raw(
            "DROP INDEX IF EXISTS dark_web_investigations_one_active_user_idx"
        ).run()
    }
}
