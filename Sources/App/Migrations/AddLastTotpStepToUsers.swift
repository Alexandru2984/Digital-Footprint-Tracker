import Fluent

/// Adds `last_totp_step` to `users` so an accepted TOTP code cannot be replayed
/// within its ±1 validity window. Nullable — null means no code has been
/// accepted yet, so no existing account is affected.
struct AddLastTotpStepToUsers: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("users").field("last_totp_step", .int64).update()
    }

    func revert(on database: Database) async throws {
        try await database.schema("users").deleteField("last_totp_step").update()
    }
}
