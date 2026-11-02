import Fluent

/// Adds to `scans` whether the target was one the scanning account had proven
/// it controls (`third_party` is true when it was not) and which checks were
/// skipped because of that (`skipped_checks`, a JSON array of plugin names).
///
/// Neither holds target data: a flag and the application's own plugin names,
/// so both are stored in the clear. Nullable and additive: older rows and the
/// previous release are unaffected.
struct AddOwnershipToScans: AsyncMigration {
    // One column per ALTER: SQLite (the test database) adds only one at a time.
    func prepare(on database: Database) async throws {
        try await database.schema("scans").field("third_party", .bool).update()
        try await database.schema("scans").field("skipped_checks", .string).update()
    }

    func revert(on database: Database) async throws {
        try await database.schema("scans").deleteField("skipped_checks").update()
        try await database.schema("scans").deleteField("third_party").update()
    }
}
