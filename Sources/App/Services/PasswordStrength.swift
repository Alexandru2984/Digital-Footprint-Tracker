import Vapor

/// Offline weak-password rejection at registration / password change.
///
/// Deliberately does NOT call the HaveIBeenPwned range API or any third party —
/// that would leak a hash prefix off-box, against the privacy-first stance. This
/// is a local blocklist of the passwords attackers try first plus a few
/// structural checks. It's a floor, not a substitute for a password manager.
enum PasswordStrength {
    /// The most-abused passwords (credential-stuffing top hits) plus obvious
    /// keyboard walks. Kept small and high-signal rather than a giant list.
    private static let blocklist: Set<String> = [
        "password", "password1", "password123", "passw0rd", "12345678", "123456789",
        "1234567890", "qwerty", "qwertyuiop", "qwerty123", "111111", "000000", "1234abcd",
        "letmein", "welcome", "welcome1", "admin", "administrator", "root", "toor",
        "iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "baseball",
        "abc123", "abcd1234", "a1b2c3d4", "changeme", "secret", "trustno1", "whatever",
        "superman", "batman", "master", "hello123", "test1234", "google", "starwars",
        "computer", "michael", "jordan", "harley", "ranger", "shadow", "hunter2",
        "zaq12wsx", "1q2w3e4r", "1qaz2wsx", "qazwsx", "asdfghjkl", "zxcvbnm",
        "your_strong_password"
    ]

    static func validate(_ password: String, username: String, email: String) throws {
        let lower = password.lowercased()

        if blocklist.contains(lower) {
            throw Abort(.badRequest, reason: "That password is one of the most commonly breached — pick something less predictable.")
        }
        // A single repeated character ("aaaaaaaa") or a pure digit run.
        if Set(password).count <= 2 {
            throw Abort(.badRequest, reason: "Password is too repetitive.")
        }
        if password.range(of: "^[0-9]+$", options: .regularExpression) != nil {
            throw Abort(.badRequest, reason: "Password can't be only digits.")
        }
        // Must not contain (or be contained by) the username / email local-part.
        let uname = username.lowercased()
        let localPart = email.lowercased().split(separator: "@").first.map(String.init) ?? ""
        if uname.count >= 3, lower.contains(uname) {
            throw Abort(.badRequest, reason: "Password must not contain your username.")
        }
        if localPart.count >= 3, lower.contains(localPart) {
            throw Abort(.badRequest, reason: "Password must not contain your email name.")
        }
        // Trivial ascending/descending sequences.
        if isSequential(lower) {
            throw Abort(.badRequest, reason: "Password is a simple sequence — mix it up.")
        }
    }

    /// True if the whole string is one monotonic ±1 run over its code points
    /// (e.g. "12345678", "abcdefgh", "87654321").
    private static func isSequential(_ s: String) -> Bool {
        let scalars = s.unicodeScalars.map { Int($0.value) }
        guard scalars.count >= 4 else { return false }
        let step = scalars[1] - scalars[0]
        guard step == 1 || step == -1 else { return false }
        for i in 1..<scalars.count where scalars[i] - scalars[i - 1] != step { return false }
        return true
    }
}
