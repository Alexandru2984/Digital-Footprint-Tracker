import Fluent
import SQLKit

struct AddInputIndex: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_scans_input ON scans (input)").run()
    }

    func revert(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }
        try await sql.raw("DROP INDEX IF EXISTS idx_scans_input").run()
    }
}
