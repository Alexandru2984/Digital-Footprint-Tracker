import Fluent
import SQLKit

/// Adds a persistent, per-scan cursor for result streaming and backfills every
/// historical result. Window functions are supported by both production
/// PostgreSQL and the SQLite version used in tests.
struct CreateScanResultEvents: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.transaction { transaction in
            try await transaction.schema(ScanResultEvent.schema)
                .field("id", .int64, .identifier(auto: true))
                .field("scan_id", .uuid, .required, .references(Scan.schema, "id", onDelete: .cascade))
                .field("result_id", .uuid, .required, .references(Result.schema, "id", onDelete: .cascade))
                .field("stream_sequence", .int64, .required)
                .unique(on: "result_id")
                .unique(on: "scan_id", "stream_sequence")
                .create()

            guard let sql = transaction as? SQLDatabase else { return }
            if sql.dialect.name.lowercased().contains("postgres") {
                // The old release remains live while the candidate migration
                // gate runs. Block inserts for this short DDL/backfill window,
                // install the compatibility trigger, then backfill under the
                // same transaction so no old-writer result can miss a cursor.
                // Fail the deployment gate instead of waiting indefinitely on
                // an unusually long live transaction.
                try await sql.raw("SET LOCAL lock_timeout = '5s'").run()
                try await sql.raw("SET LOCAL statement_timeout = '60s'").run()
                try await sql.raw("LOCK TABLE public.results IN SHARE ROW EXCLUSIVE MODE").run()
                try await sql.raw("""
                    CREATE FUNCTION public.lock_scan_result_stream_sequence()
                    RETURNS trigger
                    LANGUAGE plpgsql
                    SECURITY INVOKER
                    SET search_path = pg_catalog, public
                    AS $function$
                    BEGIN
                        PERFORM id
                        FROM public.scans
                        WHERE id = NEW.scan_id
                        FOR NO KEY UPDATE;
                        RETURN NEW;
                    END
                    $function$;
                    """).run()
                try await sql.raw("""
                    CREATE FUNCTION public.assign_scan_result_stream_sequence()
                    RETURNS trigger
                    LANGUAGE plpgsql
                    SECURITY INVOKER
                    SET search_path = pg_catalog, public
                    AS $function$
                    BEGIN
                        INSERT INTO public.scan_result_events (
                            scan_id, result_id, stream_sequence
                        )
                        SELECT NEW.scan_id,
                               NEW.id,
                               COALESCE(MAX(event.stream_sequence), 0) + 1
                        FROM public.scan_result_events AS event
                        WHERE event.scan_id = NEW.scan_id
                        ON CONFLICT (result_id) DO NOTHING;
                        RETURN NEW;
                    END
                    $function$;
                    """).run()
                try await sql.raw("""
                    CREATE TRIGGER scan_result_event_before_insert
                    BEFORE INSERT ON public.results
                    FOR EACH ROW
                    EXECUTE FUNCTION public.lock_scan_result_stream_sequence()
                    """).run()
                try await sql.raw("""
                    CREATE TRIGGER scan_result_event_after_insert
                    AFTER INSERT ON public.results
                    FOR EACH ROW
                    EXECUTE FUNCTION public.assign_scan_result_stream_sequence()
                    """).run()
                try await sql.raw("""
                    INSERT INTO public.scan_result_events (scan_id, result_id, stream_sequence)
                    SELECT scan_id,
                           id,
                           ROW_NUMBER() OVER (PARTITION BY scan_id ORDER BY id)
                    FROM public.results
                    ON CONFLICT (result_id) DO NOTHING
                    """).run()
            } else if sql.dialect.name.lowercased().contains("sqlite") {
                try await sql.raw("""
                    CREATE TRIGGER scan_result_event_after_insert
                    AFTER INSERT ON results
                    FOR EACH ROW
                    BEGIN
                        INSERT OR IGNORE INTO scan_result_events (
                            scan_id, result_id, stream_sequence
                        )
                        SELECT NEW.scan_id,
                               NEW.id,
                               COALESCE(MAX(stream_sequence), 0) + 1
                        FROM scan_result_events
                        WHERE scan_id = NEW.scan_id;
                    END
                    """).run()
                try await sql.raw("""
                    INSERT OR IGNORE INTO scan_result_events (scan_id, result_id, stream_sequence)
                    SELECT scan_id,
                           id,
                           ROW_NUMBER() OVER (PARTITION BY scan_id ORDER BY id)
                    FROM results
                    """).run()
            }
        }
    }

    func revert(on database: Database) async throws {
        try await database.transaction { transaction in
            if let sql = transaction as? SQLDatabase {
                if sql.dialect.name.lowercased().contains("postgres") {
                    try await sql.raw(
                        "DROP TRIGGER IF EXISTS scan_result_event_before_insert ON public.results"
                    ).run()
                    try await sql.raw(
                        "DROP TRIGGER IF EXISTS scan_result_event_after_insert ON public.results"
                    ).run()
                    try await sql.raw(
                        "DROP FUNCTION IF EXISTS public.lock_scan_result_stream_sequence()"
                    ).run()
                    try await sql.raw(
                        "DROP FUNCTION IF EXISTS public.assign_scan_result_stream_sequence()"
                    ).run()
                } else if sql.dialect.name.lowercased().contains("sqlite") {
                    try await sql.raw("DROP TRIGGER IF EXISTS scan_result_event_after_insert").run()
                }
            }
            try await transaction.schema(ScanResultEvent.schema).delete()
        }
    }
}
