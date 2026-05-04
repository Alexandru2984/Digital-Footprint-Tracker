import Foundation

/// Computes an aggregate exposure risk score (0–100) and level for a set of scan results.
///
/// Algorithm:
///   • Each result contributes: confidenceScore × typeWeight
///   • Breach / credential / leak findings are weighted 3×
///   • Email / phone / location findings are weighted 2×
///   • Profile / developer_identity / account are weighted 1×
///   • Weighted sum is normalised to 0–100 (cap at 20 weighted-confidence points = 100 %)
enum RiskScorer {

    enum Level: String {
        case low      = "Low"
        case medium   = "Medium"
        case high     = "High"
        case critical = "Critical"

        /// Tailwind/custom colour class used in frontend badges.
        var colour: String {
            switch self {
            case .low:      return "green"
            case .medium:   return "yellow"
            case .high:     return "orange"
            case .critical: return "red"
            }
        }
    }

    struct Score {
        let value: Int        // 0–100
        let level: Level
    }

    /// Normalisation denominator: a "fully exposed" person is expected to
    /// accumulate ≈ 20 weighted confidence points.
    private static let normCap: Double = 20.0

    static func compute(results: [Result]) -> Score {
        guard !results.isEmpty else { return Score(value: 0, level: .low) }

        var weighted = 0.0
        for r in results {
            weighted += r.confidenceScore * typeWeight(for: r.type)
        }

        let score = Int(min(100.0, (weighted / normCap) * 100.0).rounded())

        let level: Level
        switch score {
        case 0..<25:  level = .low
        case 25..<50: level = .medium
        case 50..<75: level = .high
        default:      level = .critical
        }

        return Score(value: score, level: level)
    }

    /// Quick overload accepting raw `(confidenceScore, type)` tuples —
    /// useful when the full `Result` model is not loaded.
    static func compute(raw: [(confidence: Double, type: String)]) -> Score {
        guard !raw.isEmpty else { return Score(value: 0, level: .low) }
        let weighted = raw.reduce(0.0) { $0 + $1.confidence * typeWeight(for: $1.type) }
        let score = Int(min(100.0, (weighted / normCap) * 100.0).rounded())
        let level: Level
        switch score {
        case 0..<25:  level = .low
        case 25..<50: level = .medium
        case 50..<75: level = .high
        default:      level = .critical
        }
        return Score(value: score, level: level)
    }

    private static func typeWeight(for type: String) -> Double {
        let t = type.lowercased()
        if t.contains("breach") || t.contains("credential") || t.contains("leak") || t.contains("password") {
            return 3.0
        }
        if t.contains("email") || t.contains("phone") || t.contains("location") {
            return 2.0
        }
        return 1.0
    }
}
