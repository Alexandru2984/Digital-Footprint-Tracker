import Fluent
import SQLKit

/// Adds least-privilege authorization and bounded lifetime to API keys.
/// Existing keys receive the conservative scan-only scope. Their expiry remains
/// NULL, which authentication treats as expired, so legacy unrestricted bearer
/// credentials must be deliberately reissued after deployment.
struct AddAPIKeyAuthorization: AsyncMigration {
    func prepare(on database: Database) async throws {
        // SQLite (test/development) permits one ADD COLUMN per ALTER TABLE.
        try await database.schema(APIKey.schema)
            .field("scopes", .string, .required, .sql(.default(APIKey.defaultScopesRaw)))
            .update()
        try await database.schema(APIKey.schema)
            .field("expires_at", .datetime)
            .update()
    }

    func revert(on database: Database) async throws {
        try await database.schema(APIKey.schema)
            .deleteField("scopes")
            .deleteField("expires_at")
            .update()
    }
}
