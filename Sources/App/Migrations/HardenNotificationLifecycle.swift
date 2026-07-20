import Fluent
import SQLKit

/// Aligns notification retention with the scan that produced the message.
struct HardenNotificationLifecycle: AsyncMigration {
    func prepare(on database: Database) async throws {
        guard let sql = database as? SQLDatabase,
              sql.dialect.name.lowercased().contains("postgres") else { return }

        try await sql.raw("""
            DELETE FROM scan_notifications AS notification
            WHERE NOT EXISTS (
                SELECT 1 FROM scans WHERE scans.id = notification.scan_id
            )
            """).run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS scan_notifications_scan_id_idx ON scan_notifications (scan_id)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS scan_notifications_user_created_idx ON scan_notifications (user_id, created_at DESC)").run()

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
                    WHERE constraint_row.conrelid = 'scan_notifications'::regclass
                      AND constraint_row.contype = 'f'
                      AND attribute_row.attname = 'scan_id'
                LOOP
                    EXECUTE format(
                        'ALTER TABLE scan_notifications DROP CONSTRAINT %I',
                        existing_constraint
                    );
                END LOOP;

                ALTER TABLE scan_notifications
                    ADD CONSTRAINT scan_notifications_scan_id_fkey
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE;
            END
            $migration$;
            """).run()
    }

    func revert(on database: Database) async throws {
        // No-op: rollback must not restore orphanable personal-data rows.
    }
}
