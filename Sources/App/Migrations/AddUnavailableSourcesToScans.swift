import Fluent

/// Adds `unavailable_sources` to `scans`: a JSON array of the plugin names that
/// were failing and skipped their live runs during the scan, so the results
/// page can say a source was not checked instead of implying it found nothing.
///
/// Plugin names are the application's own identifiers, never target data, so
/// the column is stored in the clear. Nullable and additive: older rows and
/// the previous release are unaffected.
struct AddUnavailableSourcesToScans: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("scans")
            .field("unavailable_sources", .string)
            .update()
    }

    func revert(on database: Database) async throws {
        try await database.schema("scans")
            .deleteField("unavailable_sources")
            .update()
    }
}
