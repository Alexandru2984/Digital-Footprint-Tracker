import Fluent

/// Makes the historical 30-day effective default explicit so `nil` can safely
/// mean the user's deliberate "Never" selection going forward.
struct DefaultUserRetention: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await User.query(on: database)
            .filter(\.$retentionDays == nil)
            .set(\.$retentionDays, to: 30)
            .update()
    }

    func revert(on database: Database) async throws {
        // Existing values cannot be distinguished from an explicit 30-day user
        // choice, so reverting must not silently erase retention preferences.
    }
}
