import Fluent
import SQLKit

struct CreatePluginCache: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("plugin_cache")
            .id()
            .field("plugin_name", .string, .required)
            .field("target_hash", .string, .required)
            .field("payload",     .string, .required)
            .field("expires_at",  .datetime, .required)
            .field("created_at",  .datetime)
            .unique(on: "plugin_name", "target_hash")
            .create()

        // Speeds up the periodic expiry sweep so it doesn't full-scan the table.
        // CREATE INDEX IF NOT EXISTS is supported by both Postgres and SQLite.
        if let sql = database as? SQLDatabase {
            do {
                try await sql.raw("""
                    CREATE INDEX IF NOT EXISTS idx_plugin_cache_expires_at
                    ON plugin_cache (expires_at)
                """).run()
            } catch {
                // Non-fatal: cleanup still works, just slower.
            }
        }
    }

    func revert(on database: Database) async throws {
        try await database.schema("plugin_cache").delete()
    }
}
