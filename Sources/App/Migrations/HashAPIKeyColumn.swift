import Fluent
import SQLKit
import Crypto
import Foundation

/// Replaces the plain-text `key` column with a SHA-256 hashed `key_hash` column,
/// back-filling existing rows in Swift to avoid any pgcrypto extension dependency.
struct HashAPIKeyColumn: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase else { return }

        // 1. Add nullable key_hash column (idempotent).
        try await sql.raw("ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_hash VARCHAR(64)").run()

        // 2. Back-fill existing rows using Swift SHA-256 (no pgcrypto needed).
        let rows = try await sql.raw("SELECT id, key FROM api_keys WHERE key_hash IS NULL").all()
        for row in rows {
            guard let id = try? row.decode(column: "id", as: UUID.self),
                  let rawKey = try? row.decode(column: "key", as: String.self) else { continue }
            let hash = sha256Hex(rawKey)
            try await sql.raw("UPDATE api_keys SET key_hash = \(bind: hash) WHERE id = \(bind: id)").run()
        }

        // 3. Make column NOT NULL.
        try await sql.raw("ALTER TABLE api_keys ALTER COLUMN key_hash SET NOT NULL").run()

        // 4. Add unique constraint on the new column (idempotent).
        try await sql.raw("ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_key_hash_key").run()
        try await sql.raw("ALTER TABLE api_keys ADD CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash)").run()

        // 5. Drop old plain-text column (automatically drops its unique constraint too).
        try await sql.raw("ALTER TABLE api_keys DROP COLUMN IF EXISTS key").run()
    }

    func revert(on database: Database) async throws {
        // Intentionally a no-op: cannot recover hashed plain-text keys.
    }
}

