import Fluent
import Foundation

final class NotificationOutboxEvent: Model {
    static let schema = "notification_outbox_events"

    struct Payload: Codable, Equatable, Sendable {
        let title: String
        let message: String
        /// Optional JSON object used by the generic webhook channel. Other
        /// channels always render the bounded title/message fields.
        let webhookBody: String?
    }

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @OptionalField(key: "scan_id") var scanID: UUID?
    @Field(key: "payload") var payloadCipher: String
    @Field(key: "idempotency_key_hash") var idempotencyKeyHash: String
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    init() {}

    init(
        id: UUID = UUID(),
        userID: UUID,
        scanID: UUID?,
        payload: Payload,
        idempotencyKeyHash: String
    ) throws {
        self.id = id
        self.$user.id = userID
        self.scanID = scanID
        self.idempotencyKeyHash = idempotencyKeyHash
        self.payloadCipher = FieldCrypto.encrypt(
            try Self.encode(payload),
            field: .notificationOutboxPayload,
            recordID: id
        )
    }

    var payload: Payload {
        get throws {
            let plaintext = try FieldCrypto.decryptStored(
                payloadCipher,
                field: .notificationOutboxPayload,
                recordID: id
            )
            guard let data = plaintext.data(using: .utf8) else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: [], debugDescription: "Notification payload is not UTF-8.")
                )
            }
            return try JSONDecoder().decode(Payload.self, from: data)
        }
    }

    func setPayload(_ payload: Payload) throws {
        guard let id else {
            preconditionFailure("NotificationOutboxEvent must have an ID before encryption")
        }
        payloadCipher = FieldCrypto.encrypt(
            try Self.encode(payload),
            field: .notificationOutboxPayload,
            recordID: id
        )
    }

    private static func encode(_ payload: Payload) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try encoder.encode(payload), as: UTF8.self)
    }
}
