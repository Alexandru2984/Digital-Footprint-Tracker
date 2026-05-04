import Fluent
import Vapor

final class User: Model, Content {
    static let schema = "users"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "username")
    var username: String

    @Field(key: "email")
    var email: String

    @Field(key: "password_hash")
    var passwordHash: String

    @Field(key: "is_admin")
    var isAdmin: Bool

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Children(for: \.$user)
    var scans: [Scan]

    init() { }

    init(id: UUID? = nil, username: String, email: String, passwordHash: String, isAdmin: Bool = false) {
        self.id = id
        self.username = username
        self.email = email
        self.passwordHash = passwordHash
        self.isAdmin = isAdmin
    }
}

extension User {
    /// Public representation — never includes the password hash.
    struct Public: Content {
        let id: UUID?
        let username: String
        let email: String
        let isAdmin: Bool
        let createdAt: Date?
    }

    func toPublic() -> Public {
        Public(id: id, username: username, email: email, isAdmin: isAdmin, createdAt: createdAt)
    }
}
