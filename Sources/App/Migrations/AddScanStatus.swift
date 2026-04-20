import Fluent
import SQLKit

struct AddScanStatus: AsyncMigration {
    func prepare(on database: Database) async throws {
        // SQLite only supports one ADD COLUMN per ALTER TABLE statement,
        // so the two fields must be added in separate schema updates.
        try await database.schema("scans")
            .field("status", .string)
            .update()

        try await database.schema("scans")
            .field("completed_at", .datetime)
            .update()

        if let sql = database as? SQLDatabase {
            try await sql.raw("UPDATE scans SET status = 'completed' WHERE status IS NULL").run()
            // These ALTER COLUMN statements are PostgreSQL-specific.
            // On other engines (e.g., SQLite used in tests) they are silently ignored.
            do {
                try await sql.raw("ALTER TABLE scans ALTER COLUMN status SET NOT NULL").run()
                try await sql.raw("ALTER TABLE scans ALTER COLUMN status SET DEFAULT 'pending'").run()
            } catch {
                // Non-PostgreSQL databases don't support ALTER COLUMN — acceptable for testing.
            }
        }
    }

    func revert(on database: Database) async throws {
        try await database.schema("scans")
            .deleteField("status")
            .deleteField("completed_at")
            .update()
    }
}
