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

    init() { }

    init(id: UUID? = nil, scanID: UUID, source: String, type: String, confidenceScore: Double, rawData: String) {
        self.id = id
        self.$scan.id = scanID
        self.source = source
        self.type = type
        self.confidenceScore = confidenceScore
        self.rawData = rawData
    }
}
