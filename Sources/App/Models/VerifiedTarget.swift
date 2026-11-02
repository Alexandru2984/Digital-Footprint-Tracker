import Fluent
import Vapor

/// An email address or domain an account has claimed, and whether it has
/// proven control of it. A proven target unlocks the checks marked
/// `requiresOwnership` and recurring monitoring for that target; see
/// `TargetOwnership`.
///
/// The value names a person or an organisation, so it is encrypted like a
/// scan's input, with a blind index for lookups. The challenge is either the
/// public token a domain owner publishes (DNS or a file on the site, so not a
/// secret) or a salted hash of the code mailed to an address, never the code.
final class VerifiedTarget: Model {
    static let schema = "verified_targets"

    enum Kind: String, Codable, Sendable { case email, domain }

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "kind") var kindRaw: String
    @Field(key: "value") var valueCipher: String
    @Field(key: "value_hash") var valueHash: String
    /// How control was proven: `email_code`, `dns_txt` or `well_known_file`.
    @OptionalField(key: "method") var method: String?
    @OptionalField(key: "challenge") var challenge: String?
    @Field(key: "attempts") var attempts: Int
    /// How many codes were mailed for this claim; bounds mail to one address.
    @Field(key: "sends") var sends: Int
    @OptionalField(key: "last_sent_at") var lastSentAt: Date?
    @OptionalField(key: "expires_at") var expiresAt: Date?
    @OptionalField(key: "verified_at") var verifiedAt: Date?
    @Timestamp(key: "created_at", on: .create) var createdAt: Date?

    var kind: Kind { Kind(rawValue: kindRaw) ?? .domain }
    var isVerified: Bool { verifiedAt != nil }

    var value: String {
        get throws {
            try FieldCrypto.decryptStored(valueCipher, field: .verifiedTargetValue, recordID: id)
        }
    }

    func setValue(_ newValue: String) {
        valueCipher = FieldCrypto.encrypt(newValue, field: .verifiedTargetValue, recordID: encryptionID)
        valueHash = FieldCrypto.blindIndex(newValue)
    }

    init() {}

    init(id: UUID? = nil, userID: UUID, kind: Kind, value: String) {
        let recordID = id ?? UUID()
        self.id = recordID
        self.$user.id = userID
        self.kindRaw = kind.rawValue
        self.valueCipher = FieldCrypto.encrypt(value, field: .verifiedTargetValue, recordID: recordID)
        self.valueHash = FieldCrypto.blindIndex(value)
        self.attempts = 0
        self.sends = 0
    }

    private var encryptionID: UUID {
        guard let id else { preconditionFailure("VerifiedTarget must have an ID before encryption") }
        return id
    }
}
