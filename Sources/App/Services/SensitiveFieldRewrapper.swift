import Fluent
import Foundation
import SQLKit
import Vapor

/// Resumable, bounded re-encryption of every sensitive database field.
///
/// Each data batch and its checkpoint are committed in the same transaction.
/// A crash therefore either preserves both or neither. New rows may be written
/// while the job runs, but every application process must already use the same
/// `ENCRYPTION_WRITE_VERSION` and active key before rotation starts.
enum SensitiveFieldRewrapper {
    static let checkpointName = "sensitive-field-rewrap-v1"

    enum Stage: String, Codable, Sendable {
        case rewrite
        case verify
    }

    enum Phase: String, Codable, CaseIterable, Sendable {
        case scans
        case results
        case investigations
        case users
        case scheduledScans = "scheduled_scans"
        case notifications
        case tags
        case auditLogs = "audit_logs"
        case darkWebInvestigations = "dark_web_investigations"
        case pluginCache = "plugin_cache"
    }

    enum Status: String, Codable, Sendable {
        case running
        case completed
    }

    struct Checkpoint: Codable, Equatable, Sendable {
        let formatVersion: Int
        let targetWriteVersion: String
        let targetKeyID: String
        var stage: Stage
        var phase: Phase
        var cursor: UUID?
        var rewrittenRows: [String: Int]
        var verifiedRows: [String: Int]
        let startedAt: Date
        var updatedAt: Date
        var completedAt: Date?
        var status: Status
    }

    struct Summary: Equatable, Sendable {
        let targetWriteVersion: String
        let targetKeyID: String
        let completed: Bool
        let stage: Stage
        let phase: Phase
        let rewrittenRows: [String: Int]
        let verifiedRows: [String: Int]

        var totalRewrittenRows: Int { rewrittenRows.values.reduce(0, +) }
        var totalVerifiedRows: Int { verifiedRows.values.reduce(0, +) }
    }

    enum Failure: Swift.Error, CustomStringConvertible, Equatable, Sendable {
        case explicitWriteVersionRequired
        case keyIDMismatch(active: String, confirmed: String)
        case invalidBatchSize
        case invalidMaximumBatches
        case incompatibleOptions
        case invalidCheckpoint
        case checkpointTargetMismatch(version: String, keyID: String)
        case rotationAlreadyRunning
        case unsupportedDatabase(String)
        case recordFailure(stage: Stage, phase: Phase, recordID: UUID?)

        var description: String {
            switch self {
            case .explicitWriteVersionRequired:
                return "ENCRYPTION_WRITE_VERSION must be explicitly set before rewrap"
            case let .keyIDMismatch(active, confirmed):
                return "confirmed key ID '\(confirmed)' does not match active key ID '\(active)'"
            case .invalidBatchSize:
                return "batch size must be between 1 and 500"
            case .invalidMaximumBatches:
                return "maximum batches must be greater than zero"
            case .incompatibleOptions:
                return "--verify-only cannot be combined with --restart or --max-batches"
            case .invalidCheckpoint:
                return "the persisted rewrap checkpoint is invalid; inspect it or use --restart"
            case let .checkpointTargetMismatch(version, keyID):
                return "an unfinished checkpoint targets write version \(version), key ID \(keyID)"
            case .rotationAlreadyRunning:
                return "another sensitive-field rewrap holds the database lock"
            case let .unsupportedDatabase(name):
                return "sensitive-field rewrap does not support database dialect '\(name)'"
            case let .recordFailure(stage, phase, recordID):
                return "sensitive-field \(stage.rawValue) failed in \(phase.rawValue) for record \(recordID?.uuidString ?? "without-id")"
            }
        }
    }

    private struct Target: Sendable {
        let version: TokenEncryption.WriteVersion
        let keyID: String
    }

    private struct BatchProgress: Sendable {
        let lastID: UUID?
        let count: Int
    }

    // Stable, application-specific PostgreSQL session advisory-lock key.
    private static let advisoryLockID: Int64 = 0x5356_4352_5950_0002

    static func run(
        on database: Database,
        confirmedKeyID: String,
        batchSize: Int = 100,
        restart: Bool = false,
        maximumBatches: Int? = nil
    ) async throws -> Summary {
        let target = try validatedTarget(
            confirmedKeyID: confirmedKeyID,
            batchSize: batchSize,
            maximumBatches: maximumBatches
        )

        return try await withExclusiveConnection(on: database) { connection in
            // Prove the keyring can open the persistent marker and rewrap that
            // marker first. An accidental key replacement fails before rows move.
            try await EncryptionKeyVerifier.verifyOrInitialize(on: connection)
            return try await resumeRewrite(
                on: connection,
                target: target,
                batchSize: batchSize,
                restart: restart,
                maximumBatches: maximumBatches
            )
        }
    }

    static func verifyOnly(
        on database: Database,
        confirmedKeyID: String,
        batchSize: Int = 100
    ) async throws -> Summary {
        let target = try validatedTarget(
            confirmedKeyID: confirmedKeyID,
            batchSize: batchSize,
            maximumBatches: nil
        )
        return try await withExclusiveConnection(on: database) { connection in
            try await EncryptionKeyVerifier.verifyOrInitialize(on: connection)
            var counts: [String: Int] = [:]
            for phase in Phase.allCases {
                var cursor: UUID?
                while true {
                    let progress = try await verifyBatch(
                        phase: phase,
                        after: cursor,
                        limit: batchSize,
                        on: connection
                    )
                    guard progress.count > 0 else { break }
                    counts[phase.rawValue, default: 0] += progress.count
                    cursor = progress.lastID
                }
            }
            return Summary(
                targetWriteVersion: target.version.rawValue,
                targetKeyID: target.keyID,
                completed: true,
                stage: .verify,
                phase: .pluginCache,
                rewrittenRows: [:],
                verifiedRows: counts
            )
        }
    }

    private static func validatedTarget(
        confirmedKeyID: String,
        batchSize: Int,
        maximumBatches: Int?
    ) throws -> Target {
        guard (1...500).contains(batchSize) else { throw Failure.invalidBatchSize }
        if let maximumBatches, maximumBatches < 1 { throw Failure.invalidMaximumBatches }
        guard let explicitVersion = Environment.get("ENCRYPTION_WRITE_VERSION")?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !explicitVersion.isEmpty else {
            throw Failure.explicitWriteVersionRequired
        }
        try TokenEncryption.validateConfiguration(required: true)
        let version = try TokenEncryption.configuredWriteVersion()
        guard explicitVersion == version.rawValue else {
            throw TokenEncryption.Error.invalidWriteVersion
        }
        let activeKeyID = try TokenEncryption.activeKeyID()
        guard confirmedKeyID == activeKeyID else {
            throw Failure.keyIDMismatch(active: activeKeyID, confirmed: confirmedKeyID)
        }
        return Target(version: version, keyID: activeKeyID)
    }

    private static func resumeRewrite(
        on database: Database,
        target: Target,
        batchSize: Int,
        restart: Bool,
        maximumBatches: Int?
    ) async throws -> Summary {
        var checkpoint: Checkpoint
        if restart {
            checkpoint = newCheckpoint(for: target)
            try await saveCheckpoint(checkpoint, on: database)
        } else if let existing = try await loadCheckpoint(on: database) {
            if existing.status == .running,
               (existing.targetWriteVersion != target.version.rawValue
                || existing.targetKeyID != target.keyID) {
                throw Failure.checkpointTargetMismatch(
                    version: existing.targetWriteVersion,
                    keyID: existing.targetKeyID
                )
            }
            if existing.status == .completed,
               (existing.targetWriteVersion != target.version.rawValue
                || existing.targetKeyID != target.keyID) {
                checkpoint = newCheckpoint(for: target)
                try await saveCheckpoint(checkpoint, on: database)
            } else {
                checkpoint = existing
            }
        } else {
            checkpoint = newCheckpoint(for: target)
            try await saveCheckpoint(checkpoint, on: database)
        }

        var batchesRun = 0
        while checkpoint.status == .running {
            if let maximumBatches, batchesRun >= maximumBatches { break }
            let current = checkpoint
            checkpoint = try await database.transaction { transaction in
                var updated = current
                let progress: BatchProgress
                switch current.stage {
                case .rewrite:
                    progress = try await rewriteBatch(
                        phase: current.phase,
                        after: current.cursor,
                        limit: batchSize,
                        on: transaction
                    )
                case .verify:
                    progress = try await verifyBatch(
                        phase: current.phase,
                        after: current.cursor,
                        limit: batchSize,
                        on: transaction
                    )
                }

                if progress.count > 0 {
                    updated.cursor = progress.lastID
                    switch current.stage {
                    case .rewrite:
                        updated.rewrittenRows[current.phase.rawValue, default: 0] += progress.count
                    case .verify:
                        updated.verifiedRows[current.phase.rawValue, default: 0] += progress.count
                    }
                } else {
                    advance(&updated)
                }
                updated.updatedAt = Date()
                try await saveCheckpoint(updated, on: transaction)
                return updated
            }
            batchesRun += 1
        }
        return summary(from: checkpoint)
    }

    private static func newCheckpoint(for target: Target) -> Checkpoint {
        let now = Date()
        return Checkpoint(
            formatVersion: 1,
            targetWriteVersion: target.version.rawValue,
            targetKeyID: target.keyID,
            stage: .rewrite,
            phase: .scans,
            cursor: nil,
            rewrittenRows: [:],
            verifiedRows: [:],
            startedAt: now,
            updatedAt: now,
            completedAt: nil,
            status: .running
        )
    }

    private static func advance(_ checkpoint: inout Checkpoint) {
        guard let index = Phase.allCases.firstIndex(of: checkpoint.phase) else {
            checkpoint.status = .completed
            checkpoint.completedAt = Date()
            checkpoint.cursor = nil
            return
        }
        let nextIndex = Phase.allCases.index(after: index)
        if nextIndex != Phase.allCases.endIndex {
            checkpoint.phase = Phase.allCases[nextIndex]
            checkpoint.cursor = nil
            return
        }
        switch checkpoint.stage {
        case .rewrite:
            checkpoint.stage = .verify
            checkpoint.phase = .scans
            checkpoint.cursor = nil
        case .verify:
            checkpoint.status = .completed
            checkpoint.completedAt = Date()
            checkpoint.cursor = nil
        }
    }

    private static func summary(from checkpoint: Checkpoint) -> Summary {
        Summary(
            targetWriteVersion: checkpoint.targetWriteVersion,
            targetKeyID: checkpoint.targetKeyID,
            completed: checkpoint.status == .completed,
            stage: checkpoint.stage,
            phase: checkpoint.phase,
            rewrittenRows: checkpoint.rewrittenRows,
            verifiedRows: checkpoint.verifiedRows
        )
    }

    private static func loadCheckpoint(on database: Database) async throws -> Checkpoint? {
        guard let row = try await EncryptionMetadata.query(on: database)
            .filter(\.$name == checkpointName)
            .first() else { return nil }
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let checkpoint = try decoder.decode(Checkpoint.self, from: Data(row.value.utf8))
            guard checkpoint.formatVersion == 1 else { throw Failure.invalidCheckpoint }
            return checkpoint
        } catch let failure as Failure {
            throw failure
        } catch {
            throw Failure.invalidCheckpoint
        }
    }

    private static func saveCheckpoint(
        _ checkpoint: Checkpoint,
        on database: Database
    ) async throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let value = String(decoding: try encoder.encode(checkpoint), as: UTF8.self)
        if let row = try await EncryptionMetadata.query(on: database)
            .filter(\.$name == checkpointName)
            .first() {
            row.value = value
            try await row.update(on: database)
        } else {
            try await EncryptionMetadata(name: checkpointName, value: value).create(on: database)
        }
    }

    private static func withExclusiveConnection<T: Sendable>(
        on database: Database,
        operation: @escaping @Sendable (Database) async throws -> T
    ) async throws -> T {
        try await database.withConnection { connection in
            guard let sql = connection as? SQLDatabase else {
                throw Failure.unsupportedDatabase("non-sql")
            }
            if sql.dialect.name == "sqlite" {
                return try await operation(connection)
            }
            guard sql.dialect.name == "postgresql" else {
                throw Failure.unsupportedDatabase(sql.dialect.name)
            }

            let rows = try await sql.raw(
                "SELECT pg_try_advisory_lock(\(bind: advisoryLockID)) AS acquired"
            ).all()
            let acquired = try rows.first?.decode(column: "acquired", as: Bool.self) ?? false
            guard acquired else { throw Failure.rotationAlreadyRunning }
            do {
                let value = try await operation(connection)
                try await sql.raw("SELECT pg_advisory_unlock(\(bind: advisoryLockID))").run()
                return value
            } catch {
                try? await sql.raw("SELECT pg_advisory_unlock(\(bind: advisoryLockID))").run()
                throw error
            }
        }
    }
}

// MARK: - Rewrite batches

private extension SensitiveFieldRewrapper {

    private static func rewriteBatch(
        phase: Phase,
        after cursor: UUID?,
        limit: Int,
        on database: Database
    ) async throws -> BatchProgress {
        switch phase {
        case .scans:
            let rows = try await scanBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    row.setInput(try row.input)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .results:
            let rows = try await resultBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    let rawData = try row.rawData
                    let metadata = try row.metadata
                    row.setRawData(rawData)
                    row.setMetadata(metadata)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .investigations:
            let rows = try await investigationBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    let name = try row.name
                    let data = try row.data
                    row.setName(name)
                    row.setData(data)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .users:
            let rows = try await userBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    let webhookURL = try row.webhookURL
                    let discordWebhookURL = try row.discordWebhookURL
                    let telegramBotToken = try row.telegramBotToken
                    let telegramChatID = try row.telegramChatID
                    let slackWebhookURL = try row.slackWebhookURL
                    let totpSecret = try row.totpSecret
                    row.setWebhookURL(webhookURL)
                    row.setDiscordWebhookURL(discordWebhookURL)
                    row.setTelegramBotToken(telegramBotToken)
                    row.setTelegramChatID(telegramChatID)
                    row.setSlackWebhookURL(slackWebhookURL)
                    row.setTOTPSecret(totpSecret)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .scheduledScans:
            let rows = try await scheduledScanBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    row.setInput(try row.input)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .notifications:
            let rows = try await notificationBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    row.setMessage(try row.message)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .tags:
            let rows = try await tagBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    row.setName(try row.name)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .auditLogs:
            let rows = try await auditLogBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    let target = try row.target
                    let ip = try row.ip
                    row.setTarget(target)
                    row.setIP(ip)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .darkWebInvestigations:
            let rows = try await darkWebBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do {
                    let target = try row.target
                    let result = try row.resultJSON
                    row.setTarget(target)
                    row.setResultJSON(result)
                    try await row.update(on: database)
                } catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        case .pluginCache:
            // Cache target hashes cannot be recomputed without the original
            // input. Purging is safe: normal scans repopulate current-format
            // entries, while retaining old hashes would require old roots.
            let rows = try await pluginCacheBatch(
                after: cursor, limit: limit, lockForUpdate: true, on: database
            )
            for row in rows {
                do { try await row.delete(on: database) }
                catch { throw recordFailure(.rewrite, phase, row.id) }
            }
            return progress(rows)
        }
    }

}

// MARK: - Verification batches

private extension SensitiveFieldRewrapper {

    private static func verifyBatch(
        phase: Phase,
        after cursor: UUID?,
        limit: Int,
        on database: Database
    ) async throws -> BatchProgress {
        switch phase {
        case .scans:
            let rows = try await scanBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                let plaintext = try decryptCurrent(
                    row.inputCipher,
                    field: .scanInput,
                    stage: .verify,
                    phase: phase,
                    id: row.id
                )
                guard row.inputHash == FieldCrypto.blindIndex(plaintext) else {
                    throw recordFailure(.verify, phase, row.id)
                }
            }
            return progress(rows)
        case .results:
            let rows = try await resultBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                try verify(row.rawDataCipher, field: .resultRawData, stage: .verify, phase: phase, id: row.id)
                try verifyOptional(row.metadataCipher, field: .resultMetadata, phase: phase, id: row.id)
            }
            return progress(rows)
        case .investigations:
            let rows = try await investigationBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                try verify(row.nameCipher, field: .investigationName, stage: .verify, phase: phase, id: row.id)
                try verify(row.dataCipher, field: .investigationData, stage: .verify, phase: phase, id: row.id)
            }
            return progress(rows)
        case .users:
            let rows = try await userBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                try verifyOptional(row.webhookURLCipher, field: .userWebhookURL, phase: phase, id: row.id)
                try verifyOptional(row.discordWebhookURLCipher, field: .userDiscordWebhookURL, phase: phase, id: row.id)
                try verifyOptional(row.telegramBotTokenCipher, field: .userTelegramBotToken, phase: phase, id: row.id)
                try verifyOptional(row.telegramChatIDCipher, field: .userTelegramChatID, phase: phase, id: row.id)
                try verifyOptional(row.slackWebhookURLCipher, field: .userSlackWebhookURL, phase: phase, id: row.id)
                try verifyOptional(row.totpSecretCipher, field: .userTOTPSecret, phase: phase, id: row.id)
            }
            return progress(rows)
        case .scheduledScans:
            let rows = try await scheduledScanBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                try verify(row.inputCipher, field: .scheduledScanInput, stage: .verify, phase: phase, id: row.id)
            }
            return progress(rows)
        case .notifications:
            let rows = try await notificationBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                try verify(row.messageCipher, field: .notificationMessage, stage: .verify, phase: phase, id: row.id)
            }
            return progress(rows)
        case .tags:
            let rows = try await tagBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                try verify(row.nameCipher, field: .tagName, stage: .verify, phase: phase, id: row.id)
            }
            return progress(rows)
        case .auditLogs:
            let rows = try await auditLogBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                try verify(row.targetCipher, field: .auditTarget, stage: .verify, phase: phase, id: row.id)
                try verify(row.ipCipher, field: .auditIP, stage: .verify, phase: phase, id: row.id)
            }
            return progress(rows)
        case .darkWebInvestigations:
            let rows = try await darkWebBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                let target = try decryptCurrent(
                    row.targetCipher,
                    field: .darkWebTarget,
                    stage: .verify,
                    phase: phase,
                    id: row.id
                )
                guard row.targetHash == FieldCrypto.blindIndex(target.lowercased()) else {
                    throw recordFailure(.verify, phase, row.id)
                }
                try verifyOptional(row.resultCipher, field: .darkWebResult, phase: phase, id: row.id)
            }
            return progress(rows)
        case .pluginCache:
            let rows = try await pluginCacheBatch(after: cursor, limit: limit, on: database)
            for row in rows {
                try verify(row.payload, field: .pluginCachePayload, stage: .verify, phase: phase, id: row.id)
            }
            return progress(rows)
        }
    }

    private static func verifyOptional(
        _ ciphertext: String?,
        field: FieldCrypto.StoredField,
        phase: Phase,
        id: UUID?
    ) throws {
        guard let ciphertext else { return }
        try verify(ciphertext, field: field, stage: .verify, phase: phase, id: id)
    }

    private static func verify(
        _ ciphertext: String,
        field: FieldCrypto.StoredField,
        stage: Stage,
        phase: Phase,
        id: UUID?
    ) throws {
        _ = try decryptCurrent(
            ciphertext,
            field: field,
            stage: stage,
            phase: phase,
            id: id
        )
    }

    private static func decryptCurrent(
        _ ciphertext: String,
        field: FieldCrypto.StoredField,
        stage: Stage,
        phase: Phase,
        id: UUID?
    ) throws -> String {
        guard let id else { throw recordFailure(stage, phase, nil) }
        do {
            return try TokenEncryption.decryptCurrentRequired(
                ciphertext,
                context: .init(field: field.rawValue, recordID: id)
            )
        } catch {
            throw recordFailure(stage, phase, id)
        }
    }

    private static func recordFailure(
        _ stage: Stage,
        _ phase: Phase,
        _ id: UUID?
    ) -> Failure {
        .recordFailure(stage: stage, phase: phase, recordID: id)
    }

    private static func progress<M: Model>(_ rows: [M]) -> BatchProgress where M.IDValue == UUID {
        BatchProgress(lastID: rows.last?.id, count: rows.count)
    }

}

// MARK: - Bounded UUID cursor queries

private extension SensitiveFieldRewrapper {

    /// Lock rewrite candidates before loading their ciphertext. This prevents a
    /// live current-key writer from changing a sensitive value between our read
    /// and update (which could otherwise lose that newer value). Verification
    /// is read-only and does not request locks. SQLite is used only in tests.
    private static func lockedRowIDs(
        schema: String,
        after cursor: UUID?,
        limit: Int,
        lockForUpdate: Bool,
        on db: Database
    ) async throws -> [UUID]? {
        guard lockForUpdate, let sql = db as? SQLDatabase,
              sql.dialect.name == "postgresql" else { return nil }
        let rows: [any SQLRow]
        if let cursor {
            rows = try await sql.raw("""
                SELECT \(ident: "id") FROM \(ident: schema)
                WHERE \(ident: "id") > \(bind: cursor)
                ORDER BY \(ident: "id") ASC LIMIT \(bind: limit) FOR UPDATE
                """).all()
        } else {
            rows = try await sql.raw("""
                SELECT \(ident: "id") FROM \(ident: schema)
                ORDER BY \(ident: "id") ASC LIMIT \(bind: limit) FOR UPDATE
                """).all()
        }
        return try rows.map { try $0.decode(column: "id", as: UUID.self) }
    }

    private static func scanBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [Scan] {
        if let ids = try await lockedRowIDs(
            schema: Scan.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await Scan.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = Scan.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func resultBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [Result] {
        if let ids = try await lockedRowIDs(
            schema: Result.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await Result.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = Result.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func investigationBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [Investigation] {
        if let ids = try await lockedRowIDs(
            schema: Investigation.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await Investigation.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = Investigation.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func userBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [User] {
        if let ids = try await lockedRowIDs(
            schema: User.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await User.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = User.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func scheduledScanBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [ScheduledScan] {
        if let ids = try await lockedRowIDs(
            schema: ScheduledScan.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await ScheduledScan.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = ScheduledScan.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func notificationBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [ScanNotification] {
        if let ids = try await lockedRowIDs(
            schema: ScanNotification.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await ScanNotification.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = ScanNotification.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func tagBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [Tag] {
        if let ids = try await lockedRowIDs(
            schema: Tag.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await Tag.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = Tag.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func auditLogBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [AuditLog] {
        if let ids = try await lockedRowIDs(
            schema: AuditLog.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await AuditLog.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = AuditLog.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func darkWebBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [DarkWebInvestigation] {
        if let ids = try await lockedRowIDs(
            schema: DarkWebInvestigation.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await DarkWebInvestigation.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = DarkWebInvestigation.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }

    private static func pluginCacheBatch(
        after cursor: UUID?, limit: Int, lockForUpdate: Bool = false, on db: Database
    ) async throws -> [PluginCacheEntry] {
        if let ids = try await lockedRowIDs(
            schema: PluginCacheEntry.schema, after: cursor, limit: limit,
            lockForUpdate: lockForUpdate, on: db
        ) {
            guard !ids.isEmpty else { return [] }
            return try await PluginCacheEntry.query(on: db)
                .filter(\.$id ~~ ids).sort(\.$id, .ascending).all()
        }
        let query = PluginCacheEntry.query(on: db).sort(\.$id, .ascending).limit(limit)
        if let cursor { query.filter(\.$id > cursor) }
        return try await query.all()
    }
}
