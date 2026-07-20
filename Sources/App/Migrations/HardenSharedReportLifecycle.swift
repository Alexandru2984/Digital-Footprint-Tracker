import Fluent
import SQLKit

/// Removes historical orphan rows and makes shared reports follow their scan's
/// lifecycle. The migration is intentionally PostgreSQL-only: fresh SQLite
/// databases receive the equivalent foreign key in CreateSharedReports.
struct HardenSharedReportLifecycle: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase,
              sql.dialect.name.lowercased().contains("postgres") else { return }

        try await sql.raw("""
            DELETE FROM shared_reports AS shared
            WHERE NOT EXISTS (
                SELECT 1 FROM scans WHERE scans.id = shared.scan_id
            )
            """).run()

        try await sql.raw("CREATE INDEX IF NOT EXISTS shared_reports_scan_id_idx ON shared_reports (scan_id)").run()

        // Fluent's generated constraint name can vary. Remove any historical
        // foreign key attached to scan_id, then install one deterministic,
        // cascading constraint rather than risking duplicate constraints.
        try await sql.raw("""
            DO $migration$
            DECLARE existing_constraint TEXT;
            BEGIN
                FOR existing_constraint IN
                    SELECT DISTINCT constraint_row.conname
                    FROM pg_constraint AS constraint_row
                    JOIN pg_attribute AS attribute_row
                      ON attribute_row.attrelid = constraint_row.conrelid
                     AND attribute_row.attnum = ANY (constraint_row.conkey)
                    WHERE constraint_row.conrelid = 'shared_reports'::regclass
                      AND constraint_row.contype = 'f'
                      AND attribute_row.attname = 'scan_id'
                LOOP
                    EXECUTE format(
                        'ALTER TABLE shared_reports DROP CONSTRAINT %I',
                        existing_constraint
                    );
                END LOOP;

                ALTER TABLE shared_reports
                    ADD CONSTRAINT shared_reports_scan_id_fkey
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE;
            END
            $migration$;
            """).run()
    }

    func revert(on database: Database) async throws {
        // Intentionally a no-op: rolling back must not restore orphanable
        // security-sensitive share credentials.
    }
}
