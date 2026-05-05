import Fluent
import SQLKit
import Crypto
import Foundation

/// Replaces the plain-text `token` column with a SHA-256 hashed `token_hash` column,
/// back-filling existing rows in Swift to avoid any pgcrypto extension dependency.
struct HashSharedReportTokens: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }

        // 1. Add nullable token_hash column (idempotent).
        try await sql.raw("ALTER TABLE shared_reports ADD COLUMN IF NOT EXISTS token_hash VARCHAR(64)").run()

        // 2. Back-fill existing rows using Swift SHA-256.
        let rows = try await sql.raw("SELECT id, token FROM shared_reports WHERE token_hash IS NULL").all()
        for row in rows {
            guard let id = try? row.decode(column: "id", as: UUID.self),
                  let rawToken = try? row.decode(column: "token", as: String.self) else { continue }
            let hash = sha256Hex(rawToken)
            try await sql.raw("UPDATE shared_reports SET token_hash = \(bind: hash) WHERE id = \(bind: id)").run()
        }

        // 3. Make column NOT NULL.
        try await sql.raw("ALTER TABLE shared_reports ALTER COLUMN token_hash SET NOT NULL").run()

        // 4. Add unique constraint on the new column (idempotent).
        try await sql.raw("ALTER TABLE shared_reports DROP CONSTRAINT IF EXISTS shared_reports_token_hash_key").run()
        try await sql.raw("ALTER TABLE shared_reports ADD CONSTRAINT shared_reports_token_hash_key UNIQUE (token_hash)").run()

        // 5. Drop old plain-text column (automatically drops its unique constraint too).
        try await sql.raw("ALTER TABLE shared_reports DROP COLUMN IF EXISTS token").run()
    }

    func revert(on database: Database) async throws {
        // Intentionally a no-op: cannot reverse a one-way hash.
    }
}

