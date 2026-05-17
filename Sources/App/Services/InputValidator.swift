import Vapor
import Foundation

/// Centralised scan-input validation.
///
/// Used by every entry point that creates or runs a scan (`/scan`, `/scan/bulk`,
/// `/scheduled-scans`, `ScheduledScanRunner`) so the same character whitelist and
/// SSRF guard are applied uniformly. Inputs that bypass any one of these checks
/// reach plugin URL templates and subprocess argv lists downstream — keep this
/// validator strict.
enum InputValidator {

    /// Trim → email-lowercase → length-cap → charset-whitelist → SSRF guard.
    ///
    /// Returns the canonical normalized form on success (use it instead of the
    /// raw input from this point on so dedup, cache, and audit keys all match).
    /// Throws `Abort(.badRequest)` with a stable reason on any failure.
    static func validateScanInput(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // Emails are case-insensitive — lowercase so `User@Example.com` and
        // `user@example.com` hit the same cache entry.
        let input = trimmed.contains("@") ? trimmed.lowercased() : trimmed

        guard !input.isEmpty else {
            throw Abort(.badRequest, reason: "Input cannot be empty.")
        }
        guard input.count <= 255 else {
            throw Abort(.badRequest, reason: "Input must be 255 characters or fewer.")
        }
        // Whitelist only characters that make sense for an email, username,
        // domain, or phone number. This blocks control characters, shell
        // metacharacters, URL fragments, and HTML — defense in depth for the
        // plugin layer (BulkUsername substitutes input into URL templates,
        // BulkEmail passes it to a subprocess).
        let allowed = CharacterSet.alphanumerics.union(.init(charactersIn: "@._+-"))
        guard input.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw Abort(.badRequest, reason: "Input contains invalid characters.")
        }
        // SSRF guard: reject targets that resolve to private / loopback /
        // link-local ranges (including cloud-metadata endpoints).
        guard !SSRFGuard.isInternalTarget(input) else {
            throw Abort(.badRequest, reason: "Scanning internal/private targets is not allowed.")
        }
        return input
    }
}
