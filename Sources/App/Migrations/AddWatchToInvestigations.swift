import Fluent
import SQLKit

/// Adds live-monitoring columns to `investigations`. `watched` is backfilled
/// FALSE and made NOT NULL on Postgres; SQLite (tests) tolerates a nullable
/// column since the app layer always writes a concrete value.
struct AddWatchToInvestigations: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("investigations").field("watched", .bool).update()
        try await database.schema("investigations").field("watch_interval", .string).update()
        try await database.schema("investigations").field("next_check_at", .datetime).update()
        try await database.schema("investigations").field("last_checked_at", .datetime).update()

        if let sql = database as? SQLDatabase {
            try await sql.raw("UPDATE investigations SET watched = FALSE WHERE watched IS NULL").run()
            do {
                try await sql.raw("ALTER TABLE investigations ALTER COLUMN watched SET NOT NULL").run()
                try await sql.raw("ALTER TABLE investigations ALTER COLUMN watched SET DEFAULT FALSE").run()
            } catch {
                // SQLite path — non-fatal.
            }
        }
    }

    func revert(on database: Database) async throws {
        try await database.schema("investigations")
            .deleteField("watched")
            .deleteField("watch_interval")
            .deleteField("next_check_at")
            .deleteField("last_checked_at")
            .update()
    }
}
