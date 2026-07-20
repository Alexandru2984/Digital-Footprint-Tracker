import Foundation

/// Conservative ASCII mailbox validation for account and SMTP boundaries.
enum EmailAddress {
    static func normalize(_ raw: String) -> String? {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !value.isEmpty, value.utf8.count <= 254,
              value.unicodeScalars.allSatisfy({
                $0.isASCII && !CharacterSet.controlCharacters.contains($0)
              }) else {
            return nil
        }

        let parts = value.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        let local = String(parts[0])
        let domain = String(parts[1])
        guard (1...64).contains(local.utf8.count),
              local.first != ".", local.last != ".", !local.contains(".."),
              local.range(
                of: #"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$"#,
                options: .regularExpression
              ) != nil else { return nil }

        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return nil }
        for label in labels {
            guard (1...63).contains(label.utf8.count),
                  label.first != "-", label.last != "-",
                  label.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }) else {
                return nil
            }
        }
        return value
    }
}
