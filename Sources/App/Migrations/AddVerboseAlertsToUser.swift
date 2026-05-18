import Fluent
import SQLKit

/// Adds an opt-in flag so users can request a notification on *every* completed
/// scheduled scan instead of only when net-new findings are detected. Default
/// behaviour is silent-unless-diff to stop spamming users who schedule many
/// scans against slow-changing targets.
struct AddVerboseAlertsToUser: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("users")
            .field("verbose_alerts", .bool)
            .update()

        if let sql = database as? SQLDatabase {
            // Backfill existing rows so the column is fully populated before
            // we mark it NOT NULL.
            try await sql.raw("UPDATE users SET verbose_alerts = FALSE WHERE verbose_alerts IS NULL").run()
            // ALTER COLUMN constraints are PostgreSQL-specific. SQLite (used in
            // the test suite) silently rejects them — that's fine, the model
            // always writes a non-null value through the app layer.
            do {
                try await sql.raw("ALTER TABLE users ALTER COLUMN verbose_alerts SET NOT NULL").run()
                try await sql.raw("ALTER TABLE users ALTER COLUMN verbose_alerts SET DEFAULT FALSE").run()
            } catch {
                // SQLite path — non-fatal.
            }
        }
    }

    func revert(on database: Database) async throws {
        try await database.schema("users")
            .deleteField("verbose_alerts")
            .update()
    }
}
