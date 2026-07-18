import Fluent
import SQLKit

/// Adds two-factor authentication (TOTP) and email-verification columns to
/// `users`. Existing accounts are grandfathered as email-verified so this
/// migration never locks anyone (including the seeded admin) out of the box;
/// only accounts created after this runs must verify.
struct AddAccountSecurityToUsers: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("users")
            .field("totp_secret", .string)
            .field("totp_enabled", .bool)
            .field("totp_recovery_codes", .string)
            .field("email_verified", .bool)
            .field("email_verification_token", .string)
            .field("email_verification_expires", .datetime)
            .update()

        if let sql = database as? SQLDatabase {
            // Backfill so the NOT NULL columns are fully populated first.
            try await sql.raw("UPDATE users SET totp_enabled = FALSE WHERE totp_enabled IS NULL").run()
            // Grandfather existing users as verified — they predate the feature.
            try await sql.raw("UPDATE users SET email_verified = TRUE WHERE email_verified IS NULL").run()
            // ALTER COLUMN constraints are PostgreSQL-specific; SQLite (tests)
            // rejects them, which is fine — the app layer always writes non-null.
            do {
                try await sql.raw("ALTER TABLE users ALTER COLUMN totp_enabled SET NOT NULL").run()
                try await sql.raw("ALTER TABLE users ALTER COLUMN totp_enabled SET DEFAULT FALSE").run()
                try await sql.raw("ALTER TABLE users ALTER COLUMN email_verified SET NOT NULL").run()
                try await sql.raw("ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT FALSE").run()
            } catch {
                // SQLite path — non-fatal.
            }
        }
    }

    func revert(on database: Database) async throws {
        try await database.schema("users")
            .deleteField("totp_secret")
            .deleteField("totp_enabled")
            .deleteField("totp_recovery_codes")
            .deleteField("email_verified")
            .deleteField("email_verification_token")
            .deleteField("email_verification_expires")
            .update()
    }
}
