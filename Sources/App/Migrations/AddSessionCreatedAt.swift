import Fluent
import SQLKit

/// Adds a `created_at` column to Vapor's `_fluent_sessions` table so the daily
/// cleanup job can prune abandoned session rows by age. The `.fluent` session
/// driver never expires rows server-side, so without this the table grows
/// unbounded for the life of the deployment.
///
/// PostgreSQL failures are intentionally fatal: silently skipping this column
/// makes the server-side session table grow without a retention boundary. The
/// column carries a `DEFAULT now()`, so `SessionRecord` inserts (which do not
/// know about it) still succeed.
struct AddSessionCreatedAt: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase,
              sql.dialect.name.lowercased().contains("postgres") else { return }
        try await sql.raw(
            "ALTER TABLE _fluent_sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
        ).run()
        try await sql.raw(
            "CREATE INDEX IF NOT EXISTS idx_fluent_sessions_created_at ON _fluent_sessions (created_at)"
        ).run()
    }

    func revert(on database: Database) async throws {
        guard let sql = database as? SQLDatabase,
              sql.dialect.name.lowercased().contains("postgres") else { return }
        try await sql.raw("DROP INDEX IF EXISTS idx_fluent_sessions_created_at").run()
        try await sql.raw("ALTER TABLE _fluent_sessions DROP COLUMN IF EXISTS created_at").run()
    }
}
