import Foundation
import Vapor

/// Strict parsing for the workers' bounded settings. Unset or blank means the
/// default; anything present but invalid fails boot rather than being guessed.
enum EnvironmentSetting {
    static func boolean(_ name: String, fallback: Bool) throws -> Bool {
        guard let raw = Environment.get(name)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else { return fallback }
        switch raw.lowercased() {
        case "1", "true", "yes": return true
        case "0", "false", "no": return false
        default: throw Abort(.internalServerError, reason: "\(name) must be an explicit boolean.")
        }
    }

    static func integer(
        _ name: String,
        fallback: Int,
        range: ClosedRange<Int>
    ) throws -> Int {
        guard let raw = Environment.get(name)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else { return fallback }
        guard let value = Int(raw), range.contains(value) else {
            throw Abort(
                .internalServerError,
                reason: "\(name) must be an integer in \(range.lowerBound)...\(range.upperBound)."
            )
        }
        return value
    }

    static func mebibytes(
        _ name: String,
        fallback: Int,
        range: ClosedRange<Int>
    ) throws -> Int {
        try integer(name, fallback: fallback, range: range) * 1_024 * 1_024
    }
}
