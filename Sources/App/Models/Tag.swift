import Fluent
import Vapor

final class Tag: Model, Content {
    static let schema = "tags"

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "name") var nameCipher: String
    var name: String {
        get throws {
            try FieldCrypto.decryptStored(nameCipher, field: .tagName, recordID: id)
        }
    }
    func setName(_ newValue: String) { nameCipher = FieldCrypto.encrypt(newValue) }
    @Field(key: "colour") var colour: String
    @Siblings(through: ScanTag.self, from: \.$tag, to: \.$scan) var scans: [Scan]

    init() {}
    init(id: UUID? = nil, userID: UUID, name: String, colour: String) {
        self.id = id
        self.$user.id = userID
        self.nameCipher = FieldCrypto.encrypt(name)
        self.colour = colour
    }
}
