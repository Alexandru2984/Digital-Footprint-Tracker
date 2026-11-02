import Fluent

/// Email addresses and domains an account has claimed, with the proof of
/// control; see `VerifiedTarget`. One row per account and target.
struct CreateVerifiedTargets: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("verified_targets")
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("kind", .string, .required)
            .field("value", .string, .required)
            .field("value_hash", .string, .required)
            .field("method", .string)
            .field("challenge", .string)
            .field("attempts", .int, .required, .sql(.default(0)))
            .field("sends", .int, .required, .sql(.default(0)))
            .field("last_sent_at", .datetime)
            .field("expires_at", .datetime)
            .field("verified_at", .datetime)
            .field("created_at", .datetime)
            .unique(on: "user_id", "value_hash")
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("verified_targets").delete()
    }
}
