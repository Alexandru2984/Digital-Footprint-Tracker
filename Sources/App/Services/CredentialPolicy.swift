import Vapor

/// One policy for every newly persisted password credential, including the
/// environment-seeded administrator. BCrypt only distinguishes the first 72
/// bytes, so accepting longer values would create surprising collisions.
enum CredentialPolicy {
    static let maximumPasswordBytes = 72

    /// Validates a username, normalizes the email, and enforces the password
    /// floor. Returns the canonical email value to persist.
    static func validateNewCredential(
        username: String,
        email: String,
        password: String,
        minimumPasswordCharacters: Int = 8
    ) throws -> String {
        guard (3...30).contains(username.count) else {
            throw Abort(.badRequest, reason: "Username must be 3–30 characters.")
        }
        guard username.range(of: "^[a-zA-Z0-9_-]+$", options: .regularExpression) != nil else {
            throw Abort(.badRequest, reason: "Username may only contain letters, numbers, hyphens and underscores.")
        }
        guard let normalizedEmail = EmailAddress.normalize(email) else {
            throw Abort(.badRequest, reason: "Invalid email address.")
        }
        guard password.count >= minimumPasswordCharacters else {
            throw Abort(
                .badRequest,
                reason: "Password must be at least \(minimumPasswordCharacters) characters."
            )
        }
        guard password.utf8.count <= maximumPasswordBytes else {
            throw Abort(.badRequest, reason: "Password must be at most 72 UTF-8 bytes.")
        }
        // Offline weak-password rejection: no identifier or hash prefix leaves
        // the server during account creation.
        try PasswordStrength.validate(password, username: username, email: normalizedEmail)
        return normalizedEmail
    }
}
