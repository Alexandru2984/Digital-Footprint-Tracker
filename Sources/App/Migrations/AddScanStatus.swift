import Fluent
import SQLKit

struct AddScanStatus: AsyncMigration {
    func prepare(on database: Database) async throws {
        // Add columns first (nullable), backfill, then enforce NOT NULL on status.
        try await database.schema("scans")
            .field("status", .string)
            .field("completed_at", .datetime)
            .update()

        if let sql = database as? SQLDatabase {
            try await sql.raw("UPDATE scans SET status = 'completed' WHERE status IS NULL").run()
            try await sql.raw("ALTER TABLE scans ALTER COLUMN status SET NOT NULL").run()
            try await sql.raw("ALTER TABLE scans ALTER COLUMN status SET DEFAULT 'pending'").run()
        }
    }

    func revert(on database: Database) async throws {
        try await database.schema("scans")
            .deleteField("status")
            .deleteField("completed_at")
            .update()
    }
}
