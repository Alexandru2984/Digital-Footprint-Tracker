import Fluent

/// Persists a result and verifies that the database trigger created its durable
/// SSE cursor in the same transaction.
///
/// Keeping ordering in the database also covers the zero-downtime migration
/// window, where the previous application release can still insert results.
enum ResultStreamStore {
    static let replayLimit = 100

    private enum StoreError: Error {
        case cursorNotCreated
    }

    static func persist(_ result: Result, on database: Database) async throws {
        let resultID = try result.requireID()

        try await database.transaction { transaction in
            try await result.create(on: transaction)
            guard try await ScanResultEvent.query(on: transaction)
                .filter(\.$result.$id == resultID)
                .first() != nil else {
                throw StoreError.cursorNotCreated
            }
        }
    }

    static func replay(
        scanID: UUID,
        after cursor: Int64,
        limit: Int = replayLimit,
        on database: Database
    ) async throws -> [ScanResultEvent] {
        try await ScanResultEvent.query(on: database)
            .filter(\.$scan.$id == scanID)
            .filter(\.$streamSequence > cursor)
            .sort(\.$streamSequence, .ascending)
            .limit(max(1, min(limit, replayLimit)))
            .with(\.$result)
            .all()
    }

    static func contains(scanID: UUID, cursor: Int64, on database: Database) async throws -> Bool {
        guard cursor > 0 else { return cursor == 0 }
        return try await ScanResultEvent.query(on: database)
            .filter(\.$scan.$id == scanID)
            .filter(\.$streamSequence == cursor)
            .first() != nil
    }
}
