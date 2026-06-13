import Fluent
import Vapor

final class Result: Model, Content {
    static let schema = "results"

    @ID(key: .id)
    var id: UUID?

    @Parent(key: "scan_id")
    var scan: Scan

    @Field(key: "source")
    var source: String

    @Field(key: "type")
    var type: String

    @Field(key: "confidence_score")
    var confidenceScore: Double

    @Field(key: "raw_data")
    var rawData: String

    /// Structured, machine-readable finding data (JSON string) — populated by
    /// plugins that emit discrete entities (username, email, url, location, …)
    /// for precise correlation and exports. Nil for plugins that haven't been
    /// migrated yet; `raw_data` remains the human-readable display string.
    @OptionalField(key: "metadata")
    var metadata: String?

    init() { }

    init(id: UUID? = nil, scanID: UUID, source: String, type: String, confidenceScore: Double, rawData: String, metadata: String? = nil) {
        self.id = id
        self.$scan.id = scanID
        self.source = source
        self.type = type
        self.confidenceScore = confidenceScore
        self.rawData = rawData
        self.metadata = metadata
    }

    /// Decodes the stored `metadata` JSON string into a dictionary for API
    /// responses and exports. Returns nil when absent or unparseable.
    var metadataObject: [String: String]? {
        guard let metadata, let data = metadata.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode([String: String].self, from: data)
    }
}
