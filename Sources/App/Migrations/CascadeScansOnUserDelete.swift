import Fluent
import SQLKit

/// `scans.user_id` was `ON DELETE SET NULL`. A scan with no owner is readable by
/// anyone holding its UUID (`ScanAccess`), so a user deleted by any path other
/// than the account-deletion handler — which removes scans explicitly first —
/// would have turned their private scans into capability-readable ones. With
/// CASCADE the database refuses to leave them behind.
/// No-op outside PostgreSQL; the test suite runs on SQLite.
struct CascadeScansOnUserDelete: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await replaceConstraint(on: database, with: """
            ALTER TABLE scans ADD CONSTRAINT scans_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            """)
    }

    func revert(on database: Database) async throws {
        try await replaceConstraint(on: database, with: """
            ALTER TABLE scans ADD CONSTRAINT scans_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            """)
    }

    private func replaceConstraint(on database: Database, with constraint: SQLQueryString) async throws {
        guard let probe = database as? SQLDatabase,
              probe.dialect.name.lowercased().contains("postgres") else { return }
        // One transaction, so the column is never briefly without a constraint.
        try await database.transaction { transaction in
            guard let sql = transaction as? SQLDatabase else { return }
            try await sql.raw("ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_user_id_fkey").run()
            try await sql.raw(constraint).run()
        }
    }
}
