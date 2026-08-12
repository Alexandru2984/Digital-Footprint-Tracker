import Fluent
import Vapor

enum DarkWebInvestigationStatus: String, Codable, Sendable {
    case pending
    case running
    case completed
    case failed
    case cancelled

    var isTerminal: Bool {
        switch self {
        case .completed, .failed, .cancelled: return true
        case .pending, .running: return false
        }
    }
}

enum DarkWebTargetKind: String, Codable, Sendable {
    case email
    case domain
    case phone
    case username

    static func detect(_ target: String) -> Self {
        if target.contains("@") { return .email }
        let phoneCharacters = CharacterSet(charactersIn: "+-0123456789")
        let digits = target.filter(\.isNumber)
        if (7...15).contains(digits.count),
           target.unicodeScalars.allSatisfy({ phoneCharacters.contains($0) }) {
            return .phone
        }
        if target.contains(".") { return .domain }
        return .username
    }
}

/// A durable, owner-scoped request for the isolated dark-web worker.
///
/// Targets and normalized results are encrypted independently at rest. The
/// external worker never receives database credentials or the encryption key;
/// the dispatcher gives it one target and validates its bounded response.
final class DarkWebInvestigation: Model {
    static let schema = "dark_web_investigations"

    @ID(key: .id)
    var id: UUID?

    @Parent(key: "user_id")
    var user: User

    @Field(key: "target")
    var targetCipher: String

    @Field(key: "target_hash")
    var targetHash: String

    var target: String {
        get { FieldCrypto.decryptStored(targetCipher) }
        set {
            targetCipher = FieldCrypto.encrypt(newValue)
            targetHash = FieldCrypto.blindIndex(newValue.lowercased())
        }
    }

    @Field(key: "target_kind")
    var targetKindRaw: String

    var targetKind: DarkWebTargetKind {
        get { DarkWebTargetKind(rawValue: targetKindRaw) ?? .username }
        set { targetKindRaw = newValue.rawValue }
    }

    @Field(key: "status")
    var statusRaw: String

    var status: DarkWebInvestigationStatus {
        get { DarkWebInvestigationStatus(rawValue: statusRaw) ?? .failed }
        set { statusRaw = newValue.rawValue }
    }

    @OptionalField(key: "result")
    var resultCipher: String?

    var resultJSON: String? {
        get { resultCipher.map(FieldCrypto.decryptStored) }
        set { resultCipher = newValue.map(FieldCrypto.encrypt) }
    }

    @Field(key: "result_count")
    var resultCount: Int

    /// Stable, non-sensitive machine code only; never persist an upstream error
    /// because it can contain the target, page content, filesystem paths or URLs.
    @OptionalField(key: "failure_code")
    var failureCode: String?

    @Field(key: "cancel_requested")
    var cancelRequested: Bool

    @Field(key: "attempt_count")
    var attemptCount: Int

    @OptionalField(key: "lease_expires_at")
    var leaseExpiresAt: Date?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @OptionalField(key: "started_at")
    var startedAt: Date?

    @OptionalField(key: "completed_at")
    var completedAt: Date?

    @Field(key: "expires_at")
    var expiresAt: Date

    init() { }

    init(userID: UUID, target: String, retentionHours: Int) {
        self.$user.id = userID
        self.target = target
        self.targetKindRaw = DarkWebTargetKind.detect(target).rawValue
        self.statusRaw = DarkWebInvestigationStatus.pending.rawValue
        self.resultCount = 0
        self.cancelRequested = false
        self.attemptCount = 0
        self.expiresAt = Date().addingTimeInterval(TimeInterval(retentionHours * 3_600))
    }
}
