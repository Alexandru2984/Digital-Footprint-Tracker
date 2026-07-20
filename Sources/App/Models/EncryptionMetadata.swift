import Fluent

final class EncryptionMetadata: Model {
    static let schema = "encryption_metadata"

    @ID(key: .id) var id: UUID?
    @Field(key: "name") var name: String
    @Field(key: "value") var value: String

    init() {}

    init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}
