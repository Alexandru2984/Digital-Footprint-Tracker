import Fluent
import SQLKit

/// PostgreSQL does not index a foreign key on its own. Nine had no supporting
/// index, `results.scan_id` among them — the column every results view, export
/// and diff filters on. Without these, each such read scans the whole child
/// table, and so does every `ON DELETE CASCADE` for each parent row removed, so
/// retention cleanup of many old scans degrades quadratically as data grows.
///
/// `(user_id, created_at)` on scans also serves the newest-first scan lists.
/// No-op outside PostgreSQL; the test suite runs on SQLite.
struct IndexForeignKeys: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase,
              sql.dialect.name.lowercased().contains("postgres") else { return }
        // Literal statements: nothing here is interpolated, so the project's
        // "every raw SQL interpolation is a bind" invariant stays checkable.
        for statement: SQLQueryString in [
            "CREATE INDEX IF NOT EXISTS idx_results_scan_id ON results (scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans (user_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_investigations_user_id ON investigations (user_id)",
            "CREATE INDEX IF NOT EXISTS idx_scheduled_scans_user_id ON scheduled_scans (user_id)",
            "CREATE INDEX IF NOT EXISTS idx_tags_user_id ON tags (user_id)",
            "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys (user_id)",
            "CREATE INDEX IF NOT EXISTS idx_scan_tags_tag_id ON scan_tags (tag_id)",
            "CREATE INDEX IF NOT EXISTS idx_export_jobs_scan_id ON export_jobs (scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_notification_outbox_events_scan_id ON notification_outbox_events (scan_id)",
        ] {
            try await sql.raw(statement).run()
        }
    }

    func revert(on database: Database) async throws {
        guard let sql = database as? SQLDatabase,
              sql.dialect.name.lowercased().contains("postgres") else { return }
        for statement: SQLQueryString in [
            "DROP INDEX IF EXISTS idx_results_scan_id",
            "DROP INDEX IF EXISTS idx_scans_user_created",
            "DROP INDEX IF EXISTS idx_investigations_user_id",
            "DROP INDEX IF EXISTS idx_scheduled_scans_user_id",
            "DROP INDEX IF EXISTS idx_tags_user_id",
            "DROP INDEX IF EXISTS idx_api_keys_user_id",
            "DROP INDEX IF EXISTS idx_scan_tags_tag_id",
            "DROP INDEX IF EXISTS idx_export_jobs_scan_id",
            "DROP INDEX IF EXISTS idx_notification_outbox_events_scan_id",
        ] {
            try await sql.raw(statement).run()
        }
    }
}
