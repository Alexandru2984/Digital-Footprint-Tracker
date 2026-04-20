import Fluent
import Vapor

final class Scan: Model, Content {
    static let schema = "scans"
    
    @ID(key: .id)
    var id: UUID?

    @Field(key: "input")
    var input: String

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Children(for: \.$scan)
    var results: [Result]

    init() { }

    init(id: UUID? = nil, input: String) {
        self.id = id
        self.input = input
    }
}
