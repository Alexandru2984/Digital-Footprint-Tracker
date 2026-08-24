import Fluent
import Foundation
import SQLKit
import Vapor

enum NotificationOutbox {
    static let maximumTitleBytes = 512
    static let maximumMessageBytes = 64 * 1_024
    static let maximumWebhookBodyBytes = 64 * 1_024

    struct Receipt: Equatable, Sendable {
        let eventID: UUID
        let jobIDs: [UUID]
    }

    enum EnqueueError: Swift.Error, Equatable, Sendable {
        case emptyIdempotencyKey
        case idempotencyKeyTooLarge
        case payloadTooLarge
        case noChannels
        case unsupportedDatabase
        case eventNotPersisted
    }

    /// Atomically persists one encrypted event and one idempotent delivery row
    /// per selected channel. `ON CONFLICT DO NOTHING` makes concurrent producer
    /// retries safe on both PostgreSQL and the SQLite test database.
    static func enqueue(
        userID: UUID,
        title: String,
        message: String,
        scanID: UUID?,
        idempotencyKey: String,
        channels: Set<NotificationChannel> = Set(NotificationChannel.allCases),
        app: Application
    ) async throws -> Receipt {
        guard !idempotencyKey.isEmpty else { throw EnqueueError.emptyIdempotencyKey }
        guard idempotencyKey.utf8.count <= 512 else { throw EnqueueError.idempotencyKeyTooLarge }
        guard !channels.isEmpty else { throw EnqueueError.noChannels }
        guard title.utf8.count <= maximumTitleBytes,
              message.utf8.count <= maximumMessageBytes else {
            throw EnqueueError.payloadTooLarge
        }

        return try await persist(
            userID: userID,
            payload: .init(title: title, message: message, webhookBody: nil),
            scanID: scanID,
            idempotencyKey: idempotencyKey,
            channels: channels,
            maxAttempts: app.notificationDeliveryConfiguration.maxAttempts,
            on: app.db
        )
    }

    static func enqueueWebhook(
        userID: UUID,
        title: String,
        message: String,
        webhookBody: String,
        scanID: UUID,
        idempotencyKey: String,
        app: Application
    ) async throws -> Receipt {
        guard webhookBody.utf8.count <= maximumWebhookBodyBytes else {
            throw EnqueueError.payloadTooLarge
        }
        guard title.utf8.count <= maximumTitleBytes,
              message.utf8.count <= maximumMessageBytes else {
            throw EnqueueError.payloadTooLarge
        }
        guard !idempotencyKey.isEmpty else { throw EnqueueError.emptyIdempotencyKey }
        guard idempotencyKey.utf8.count <= 512 else { throw EnqueueError.idempotencyKeyTooLarge }

        return try await persist(
            userID: userID,
            payload: .init(title: title, message: message, webhookBody: webhookBody),
            scanID: scanID,
            idempotencyKey: idempotencyKey,
            channels: [.webhook],
            maxAttempts: app.notificationDeliveryConfiguration.maxAttempts,
            on: app.db
        )
    }

    private static func persist(
        userID: UUID,
        payload: NotificationOutboxEvent.Payload,
        scanID: UUID?,
        idempotencyKey: String,
        channels: Set<NotificationChannel>,
        maxAttempts: Int,
        on database: Database
    ) async throws -> Receipt {
        guard database is SQLDatabase else { throw EnqueueError.unsupportedDatabase }
        let eventID = UUID()
        let idempotencyHash = sha256Hex(
            "notification-outbox-v1|\(userID.uuidString.lowercased())|\(idempotencyKey)"
        )
        let candidate = try NotificationOutboxEvent(
            id: eventID,
            userID: userID,
            scanID: scanID,
            payload: payload,
            idempotencyKeyHash: idempotencyHash
        )
        let now = Date()

        return try await database.transaction { transaction in
            guard let sql = transaction as? SQLDatabase else {
                throw EnqueueError.unsupportedDatabase
            }
            if let scanID {
                try await sql.raw("""
                    INSERT INTO notification_outbox_events
                        (id, user_id, scan_id, payload, idempotency_key_hash, created_at)
                    VALUES
                        (\(bind: eventID), \(bind: userID), \(bind: scanID),
                         \(bind: candidate.payloadCipher), \(bind: idempotencyHash), \(bind: now))
                    ON CONFLICT (user_id, idempotency_key_hash) DO NOTHING
                    """).run()
            } else {
                try await sql.raw("""
                    INSERT INTO notification_outbox_events
                        (id, user_id, scan_id, payload, idempotency_key_hash, created_at)
                    VALUES
                        (\(bind: eventID), \(bind: userID), NULL,
                         \(bind: candidate.payloadCipher), \(bind: idempotencyHash), \(bind: now))
                    ON CONFLICT (user_id, idempotency_key_hash) DO NOTHING
                    """).run()
            }

            guard let storedEvent = try await NotificationOutboxEvent.query(on: transaction)
                .filter(\.$user.$id == userID)
                .filter(\.$idempotencyKeyHash == idempotencyHash)
                .first(),
                  let storedEventID = storedEvent.id else {
                throw EnqueueError.eventNotPersisted
            }

            for channel in channels.sorted(by: { $0.rawValue < $1.rawValue }) {
                let jobID = UUID()
                try await sql.raw("""
                    INSERT INTO notification_delivery_jobs
                        (id, event_id, channel, status, attempt_count, max_attempts,
                         next_attempt_at, created_at, updated_at)
                    VALUES
                        (\(bind: jobID), \(bind: storedEventID), \(bind: channel.rawValue),
                         \(bind: NotificationDeliveryJobStatus.pending.rawValue), 0,
                         \(bind: maxAttempts), \(bind: now), \(bind: now), \(bind: now))
                    ON CONFLICT (event_id, channel) DO NOTHING
                    """).run()
            }

            let jobs = try await NotificationDeliveryJob.query(on: transaction)
                .filter(\.$event.$id == storedEventID)
                .sort(\.$channelRaw, .ascending)
                .all()
            return Receipt(eventID: storedEventID, jobIDs: jobs.compactMap(\.id))
        }
    }
}
