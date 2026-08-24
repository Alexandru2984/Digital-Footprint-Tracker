import Fluent
import Foundation
import SQLKit

struct CreateAuditIntegrityLedger: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.transaction { transaction in
            try await transaction.schema(AuditIntegrityHead.schema)
                .id()
                .field("last_sequence", .int64, .required)
                .field("head_hash", .string, .required)
                .field("started_at", .datetime, .required)
                .field("updated_at", .datetime, .required)
                .create()

            try await transaction.schema(AuditIntegrityEvent.schema)
                .id()
                .field("sequence", .int64, .required)
                .field("kind", .string, .required)
                .field("audit_log_id", .uuid, .required)
                .field("payload_hash", .string, .required)
                .field("previous_hash", .string, .required)
                .field("entry_hash", .string, .required)
                .field("signature", .string, .required)
                .field("signing_key_id", .string, .required)
                .field("public_key", .string, .required)
                .field("recorded_at", .datetime, .required)
                .unique(on: "sequence")
                .unique(on: "entry_hash")
                .create()

            try await AuditIntegrityHead(startedAt: Date()).create(on: transaction)

            guard let sql = transaction as? SQLDatabase else { return }
            try await sql.raw("""
                CREATE INDEX IF NOT EXISTS audit_integrity_events_log_sequence_idx
                ON audit_integrity_events (audit_log_id, sequence)
                """).run()

            if sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw("""
                    ALTER TABLE audit_integrity_events
                      ADD CONSTRAINT audit_integrity_events_sequence_check CHECK (sequence > 0),
                      ADD CONSTRAINT audit_integrity_events_kind_check
                        CHECK (kind IN ('entry', 'redaction', 'retention')),
                      ADD CONSTRAINT audit_integrity_events_hash_check
                        CHECK (
                          payload_hash ~ '^[0-9a-f]{64}$'
                          AND previous_hash ~ '^[0-9a-f]{64}$'
                          AND entry_hash ~ '^[0-9a-f]{64}$'
                        )
                    """).run()
                try await sql.raw("""
                    CREATE FUNCTION public.reject_audit_integrity_event_mutation()
                    RETURNS trigger
                    LANGUAGE plpgsql
                    SECURITY INVOKER
                    SET search_path = pg_catalog, public
                    AS $function$
                    BEGIN
                        RAISE EXCEPTION 'audit integrity events are append-only'
                            USING ERRCODE = '55000';
                    END
                    $function$;
                    """).run()
                try await sql.raw("""
                    CREATE TRIGGER audit_integrity_events_no_row_mutation
                    BEFORE UPDATE OR DELETE ON public.audit_integrity_events
                    FOR EACH ROW
                    EXECUTE FUNCTION public.reject_audit_integrity_event_mutation()
                    """).run()
                try await sql.raw("""
                    CREATE TRIGGER audit_integrity_events_no_truncate
                    BEFORE TRUNCATE ON public.audit_integrity_events
                    FOR EACH STATEMENT
                    EXECUTE FUNCTION public.reject_audit_integrity_event_mutation()
                    """).run()
            } else if sql.dialect.name.lowercased().contains("sqlite") {
                try await sql.raw("""
                    CREATE TRIGGER audit_integrity_events_no_update
                    BEFORE UPDATE ON audit_integrity_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit integrity events are append-only');
                    END
                    """).run()
                try await sql.raw("""
                    CREATE TRIGGER audit_integrity_events_no_delete
                    BEFORE DELETE ON audit_integrity_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit integrity events are append-only');
                    END
                    """).run()
            }
        }
    }

    func revert(on database: Database) async throws {
        try await database.transaction { transaction in
            if let sql = transaction as? SQLDatabase,
               sql.dialect.name.lowercased().contains("postgres") {
                try await sql.raw(
                    "DROP FUNCTION IF EXISTS public.reject_audit_integrity_event_mutation() CASCADE"
                ).run()
            }
            try await transaction.schema(AuditIntegrityEvent.schema).delete()
            try await transaction.schema(AuditIntegrityHead.schema).delete()
        }
    }
}
