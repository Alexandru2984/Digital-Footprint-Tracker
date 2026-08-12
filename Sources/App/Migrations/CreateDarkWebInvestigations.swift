import Fluent
import SQLKit

struct CreateDarkWebInvestigations: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema(DarkWebInvestigation.schema)
            .id()
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("target", .string, .required)
            .field("target_hash", .string, .required)
            .field("target_kind", .string, .required)
            .field("status", .string, .required)
            .field("result", .string)
            .field("result_count", .int, .required)
            .field("failure_code", .string)
            .field("cancel_requested", .bool, .required)
            .field("attempt_count", .int, .required)
            .field("lease_expires_at", .datetime)
            .field("created_at", .datetime)
            .field("started_at", .datetime)
            .field("completed_at", .datetime)
            .field("expires_at", .datetime, .required)
            .create()

        if let sql = database as? SQLDatabase {
            try await sql.raw(
                "CREATE INDEX dark_web_investigations_user_created_idx " +
                "ON dark_web_investigations (user_id, created_at)"
            ).run()
            try await sql.raw(
                "CREATE INDEX dark_web_investigations_status_created_idx " +
                "ON dark_web_investigations (status, created_at)"
            ).run()
            try await sql.raw(
                "CREATE INDEX dark_web_investigations_expires_idx " +
                "ON dark_web_investigations (expires_at)"
            ).run()
        }
    }

    func revert(on database: Database) async throws {
        try await database.schema(DarkWebInvestigation.schema).delete()
    }
}
