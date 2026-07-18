import Fluent
import SQLKit

/// Adds the blind-index column for encrypted scan inputs. No backfill: rows
/// created before this keep their plaintext `input` (and a null `input_hash`) and
/// are matched by the legacy equality branch in `QueryBuilder.filterInput`; new
/// rows store ciphertext + a populated `input_hash`. Old rows age out via
/// retention, so the plaintext surface shrinks over time on its own.
struct AddInputHashToScans: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("scans").field("input_hash", .string).update()
        if let sql = database as? SQLDatabase {
            try await sql.raw("CREATE INDEX IF NOT EXISTS idx_scans_input_hash ON scans (input_hash)").run()
        }
    }

    func revert(on database: Database) async throws {
        if let sql = database as? SQLDatabase {
            try await sql.raw("DROP INDEX IF EXISTS idx_scans_input_hash").run()
        }
        try await database.schema("scans").deleteField("input_hash").update()
    }
}
