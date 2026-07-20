import Fluent
import Vapor

final class Tag: Model, Content {
    static let schema = "tags"

    @ID(key: .id) var id: UUID?
    @Parent(key: "user_id") var user: User
    @Field(key: "name") var nameCipher: String
    var name: String {
        get { FieldCrypto.decryptStored(nameCipher) }
        set { nameCipher = FieldCrypto.encrypt(newValue) }
    }
    @Field(key: "colour") var colour: String
    @Siblings(through: ScanTag.self, from: \.$tag, to: \.$scan) var scans: [Scan]

    init() {}
    init(id: UUID? = nil, userID: UUID, name: String, colour: String) {
        self.id = id
        self.$user.id = userID
        self.name = name
        self.colour = colour
    }
}
