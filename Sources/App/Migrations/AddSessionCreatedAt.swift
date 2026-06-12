import Fluent
import SQLKit

/// Adds a `created_at` column to Vapor's `_fluent_sessions` table so the daily
/// cleanup job can prune abandoned session rows by age. The `.fluent` session
/// driver never expires rows server-side, so without this the table grows
/// unbounded for the life of the deployment.
///
/// Deliberately defensive: any failure here is logged and swallowed so a schema
/// quirk in Vapor's internal session table can never block application boot.
/// The column carries a `DEFAULT now()`, so `SessionRecord` inserts (which don't
/// know about it) still succeed.
struct AddSessionCreatedAt: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }
        do {
            try await sql.raw(
                "ALTER TABLE _fluent_sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ).run()
            try await sql.raw(
                "CREATE INDEX IF NOT EXISTS idx_fluent_sessions_created_at ON _fluent_sessions (created_at)"
            ).run()
        } catch {
            database.logger.warning("AddSessionCreatedAt: skipped (\(error))")
        }
    }

    func revert(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }
        try? await sql.raw("DROP INDEX IF EXISTS idx_fluent_sessions_created_at").run()
        try? await sql.raw("ALTER TABLE _fluent_sessions DROP COLUMN IF EXISTS created_at").run()
    }
}
