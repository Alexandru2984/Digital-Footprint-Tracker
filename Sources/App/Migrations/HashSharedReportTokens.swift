import Fluent
import SQLKit
import Crypto
import Foundation

/// Replaces the plain-text `token` column with a SHA-256 hashed `token_hash` column,
/// back-filling existing rows in Swift to avoid any pgcrypto extension dependency.
struct HashSharedReportTokens: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }

        // 1. Add nullable token_hash column (idempotent). Fresh databases
        // already have this final column from CreateSharedReports.
        try await sql.raw("ALTER TABLE shared_reports ADD COLUMN IF NOT EXISTS token_hash VARCHAR(64)").run()

        // 2. Back-fill legacy rows only when the old plaintext column exists.
        // An unconditional SELECT token made a fresh install fail at migration.
        let existence = try await sql.raw("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'shared_reports'
                  AND column_name = 'token'
            ) AS present
            """).first()
        let legacyTokenExists = existence.flatMap {
            try? $0.decode(column: "present", as: Bool.self)
        } ?? false
        if legacyTokenExists {
            let rows = try await sql.raw("SELECT id, token FROM shared_reports WHERE token_hash IS NULL").all()
            for row in rows {
                guard let id = try? row.decode(column: "id", as: UUID.self),
                      let rawToken = try? row.decode(column: "token", as: String.self) else { continue }
                let hash = sha256Hex(rawToken)
                try await sql.raw("UPDATE shared_reports SET token_hash = \(bind: hash) WHERE id = \(bind: id)").run()
            }
        }

        // 3. Make column NOT NULL.
        try await sql.raw("ALTER TABLE shared_reports ALTER COLUMN token_hash SET NOT NULL").run()

        // 4. Add a unique constraint unless the fresh schema already supplied
        // one under Fluent's generated name. This avoids a redundant unique
        // index on every clean PostgreSQL installation.
        let uniqueExistence = try await sql.raw("""
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.table_constraints AS constraint_row
                JOIN information_schema.constraint_column_usage AS column_row
                  ON column_row.constraint_schema = constraint_row.constraint_schema
                 AND column_row.constraint_name = constraint_row.constraint_name
                WHERE constraint_row.table_schema = current_schema()
                  AND constraint_row.table_name = 'shared_reports'
                  AND constraint_row.constraint_type = 'UNIQUE'
                  AND column_row.column_name = 'token_hash'
            ) AS present
            """).first()
        let uniqueExists = uniqueExistence.flatMap {
            try? $0.decode(column: "present", as: Bool.self)
        } ?? false
        if !uniqueExists {
            try await sql.raw("ALTER TABLE shared_reports ADD CONSTRAINT shared_reports_token_hash_key UNIQUE (token_hash)").run()
        }

        // 5. Drop old plain-text column (automatically drops its unique constraint too).
        try await sql.raw("ALTER TABLE shared_reports DROP COLUMN IF EXISTS token").run()
    }

    func revert(on database: Database) async throws {
        // Intentionally a no-op: cannot reverse a one-way hash.
    }
}
