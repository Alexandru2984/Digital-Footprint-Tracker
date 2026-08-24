import Fluent
import SQLKit

struct CreateExportJobs: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema(ExportJob.schema)
            .id()
            .field(
                "user_id", .uuid, .required,
                .references(User.schema, "id", onDelete: .cascade)
            )
            .field(
                "scan_id", .uuid, .required,
                .references(Scan.schema, "id", onDelete: .cascade)
            )
            .field("format", .string, .required)
            .field("status", .string, .required)
            .field("progress_completed", .int, .required)
            .field("progress_total", .int, .required)
            .field("artifact", .string)
            .field("manifest", .string)
            .field("failure_code", .string)
            .field("cancel_requested", .bool, .required)
            .field("attempt_count", .int, .required)
            .field("max_attempts", .int, .required)
            .field("lease_owner", .string)
            .field("lease_expires_at", .datetime)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .field("started_at", .datetime)
            .field("completed_at", .datetime)
            .field("expires_at", .datetime, .required)
            .create()

        guard let sql = database as? SQLDatabase else { return }
        try await sql.raw("""
            CREATE INDEX IF NOT EXISTS export_jobs_user_created_idx
            ON export_jobs (user_id, created_at)
            """).run()
        try await sql.raw("""
            CREATE INDEX IF NOT EXISTS export_jobs_status_due_idx
            ON export_jobs (status, created_at)
            """).run()
        try await sql.raw("""
            CREATE INDEX IF NOT EXISTS export_jobs_lease_idx
            ON export_jobs (status, lease_expires_at)
            """).run()
        try await sql.raw("""
            CREATE INDEX IF NOT EXISTS export_jobs_expires_idx
            ON export_jobs (expires_at)
            """).run()

        guard sql.dialect.name.lowercased().contains("postgres") else { return }
        try await sql.raw("""
            ALTER TABLE export_jobs
              ADD CONSTRAINT export_jobs_format_check
                CHECK (format IN ('json', 'graphml', 'markdown', 'html', 'pdf')),
              ADD CONSTRAINT export_jobs_status_check
                CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
              ADD CONSTRAINT export_jobs_progress_check
                CHECK (progress_completed >= 0 AND progress_total >= 0),
              ADD CONSTRAINT export_jobs_attempt_check
                CHECK (
                  max_attempts BETWEEN 1 AND 3
                  AND attempt_count BETWEEN 0 AND max_attempts
                ),
              ADD CONSTRAINT export_jobs_lease_state_check
                CHECK (
                  (status = 'processing' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
                  OR
                  (status <> 'processing' AND lease_owner IS NULL AND lease_expires_at IS NULL)
                ),
              ADD CONSTRAINT export_jobs_artifact_state_check
                CHECK (
                  (status = 'completed' AND artifact IS NOT NULL AND manifest IS NOT NULL)
                  OR
                  (status <> 'completed' AND artifact IS NULL AND manifest IS NULL)
                ),
              ADD CONSTRAINT export_jobs_failure_state_check
                CHECK (
                  (status = 'failed' AND failure_code IS NOT NULL)
                  OR
                  (status <> 'failed' AND failure_code IS NULL)
                )
            """).run()
    }

    func revert(on database: Database) async throws {
        try await database.schema(ExportJob.schema).delete()
    }
}
